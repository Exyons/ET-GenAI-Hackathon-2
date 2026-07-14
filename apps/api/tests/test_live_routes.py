from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from prahari.api.models import AttributionView, TechniqueView
from prahari.live import state
from prahari.live.fleet import Fleet
from prahari.main import app
from prahari.schema import CanonicalEvent

client = TestClient(app)
TOKEN = {"Authorization": "Bearer dev-token"}


def _at(h, m, s):
    return datetime(2017, 7, 5, h, m, s, tzinfo=timezone.utc)


def _ev(ts, et, source, **kw):
    return CanonicalEvent(timestamp=ts, event_type=et, source=source, raw="x", **kw)


def _json(events):
    return [e.model_dump(mode="json") for e in events]


def _benign():
    e = [_ev(_at(15, 0, i), "auth", "linux-auth", source_entity="U100", src_host="WU100",
            dst_host="C2", auth_type="Kerberos", outcome="success", asset_criticality="medium")
         for i in range(12)]
    e += [_ev(_at(15, 0, i), "network_flow", "conntrack", src_host="WU100", dst_ip="10.0.0.9",
             bytes=200 + i, duration=1.0, src_internal=True) for i in range(6)]
    return e


def _attack():
    return [
        _ev(_at(3, 32, 16), "auth", "linux-auth", source_entity="U100", src_host="WU100",
            dst_host="C553", auth_type="NTLM", outcome="success", asset_criticality="critical"),
        _ev(_at(3, 32, 19), "process", "sysmon", source_entity="U100", src_host="C553",
            dest_entity="cmd /c whoami", asset_criticality="critical"),
        _ev(_at(3, 32, 24), "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17",
            bytes=54000, duration=900.0, src_internal=False, asset_criticality="critical"),
    ]


@pytest.fixture(autouse=True)
def reset_pipeline(tmp_path):
    p = state.pipeline
    p.warmup_seconds = 0
    p.state_dir = str(tmp_path)
    p.attribute_fn = lambda inc: AttributionView(
        technique_ids=["T1021.006"],
        techniques=[TechniqueView(id="T1021.006", name="Remote Services", tactic="lateral-movement")],
        explanation="x", grounded=True, predicted_next="exfiltration")
    p.mode = "warmup"
    p._t0 = None
    p.warmup_events = []
    p.recent.clear()
    p.incidents.clear()
    p.attributions.clear()
    p._high_conf.clear()
    p.auth_sentinel = p.net_sentinel = None
    p.auth_threshold = p.net_threshold = None
    p.fleet = Fleet()
    p.process_baseline = set()
    p._seen_flags = {}
    p.stats.clear()
    p.activity.clear()
    yield


def test_ingest_rejects_bad_token():
    assert client.post("/api/ingest", json=[]).status_code == 401
    assert client.post("/api/ingest", json=[], headers={"Authorization": "Bearer nope"}).status_code == 401


def test_status_shape():
    r = client.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"mode", "events_seen", "warmup_remaining_s", "warmup_seconds",
                         "incident_count", "high_confidence_count", "flagged_recent",
                         "baseline_ready", "fleet", "pipeline"}
    assert set(body["fleet"]) == {"hosts", "by_type", "series", "rate_epm"}
    assert set(body["pipeline"]) == {"stats", "activity", "window_seconds",
                                     "process_baseline_size", "detectors",
                                     "models", "attribution_error"}


def test_baseline_reset_requires_token_and_warms_up():
    assert client.post("/api/baseline/reset").status_code == 401
    r = client.post("/api/baseline/reset", headers=TOKEN)
    assert r.status_code == 200 and r.json()["mode"] == "warmup"


def test_incidents_live_only_and_demo_route():
    assert client.get("/api/incidents").json() == []  # no idle fallback on the live route
    ids = [i["id"] for i in client.get("/api/demo/incidents").json()]
    assert "inc-c553" in ids  # canned scenario lives under /api/demo


def test_heartbeat_registers_host_without_events():
    r = client.post("/api/ingest", json=[], headers={
        **TOKEN, "X-Prahari-Host": "cachyos-btw", "X-Prahari-Os": "linux",
        "X-Prahari-Sources": "linux-auth,linux-conntrack",
        "X-Prahari-Source-Status": '{"auth": {"state": "tailing", "detail": "", "n": 0}, '
                                   '"network": {"state": "error", "detail": "\'conntrack\' not installed", "n": 0}}'})
    assert r.status_code == 200 and r.json()["accepted"] == 0
    (h,) = client.get("/api/status").json()["fleet"]["hosts"]
    assert h["host"] == "cachyos-btw" and h["os"] == "linux"
    assert h["sources"] == ["linux-auth", "linux-conntrack"]
    assert h["total"] == 0 and h["last_seen_s"] < 5
    assert h["agent"]["auth"]["state"] == "tailing"
    assert "conntrack" in h["agent"]["network"]["detail"]


def test_recent_events_tape():
    assert client.get("/api/events/recent").json() == []
    client.post("/api/ingest", json=_json(_benign()), headers=TOKEN)
    tape = client.get("/api/events/recent").json()
    assert len(tape) == 18
    assert {"timestamp", "event_type", "phase", "source", "actor", "detail",
            "host", "flagged"} <= set(tape[0])
    assert len(client.get("/api/events/recent?limit=5").json()) == 5
    assert client.get("/api/events/recent?limit=0").status_code == 422


def test_flagged_events_window():
    assert client.get("/api/events/flagged").json() == []
    client.post("/api/ingest", json=_json(_benign()), headers=TOKEN)
    client.post("/api/ingest", json=_json(_attack()), headers=TOKEN)
    flagged = client.get("/api/events/flagged").json()
    assert len(flagged) >= 1
    assert all(e["flagged"] is True for e in flagged)
    assert any(e["host"] == "C553" for e in flagged)


def test_live_incident_after_attack():
    assert client.post("/api/ingest", json=_json(_benign()), headers=TOKEN).status_code == 200
    r = client.post("/api/ingest", json=_json(_attack()), headers=TOKEN)
    assert r.status_code == 200 and r.json()["mode"] == "monitoring"

    ids = [i["id"] for i in client.get("/api/incidents").json()]
    assert "inc-c553" in ids
    detail = client.get("/api/incidents/inc-c553").json()
    assert detail["attribution"]["technique_ids"] == ["T1021.006"]
    assert len(detail["timeline"]) == 3

    # incident-scoped event views (KPI drill-downs)
    evts = client.get("/api/events/incidents").json()
    assert any(e["incident"] == "inc-c553" for e in evts)
    high = client.get("/api/events/incidents?high=true").json()
    assert {e["incident"] for e in high} == {"inc-c553"}

    # pipeline activity narrates the stages
    act = client.get("/api/status").json()["pipeline"]["activity"]
    stages = {a["stage"] for a in act}
    assert {"baseline", "sentinel", "correlator", "attribution"} <= stages
