import asyncio
from datetime import datetime, timezone

from prahari.api.models import AttributionView, TechniqueView
from prahari.live.baseline import (
    delete_baseline,
    load_baseline,
    save_baseline,
    screen_warmup,
)
from prahari.live.baseline import _path as baseline_path
from prahari.live.bus import EventBus
from prahari.live.pipeline import LivePipeline
from prahari.schema import CanonicalEvent


def _at(h, m, s):
    return datetime(2017, 7, 5, h, m, s, tzinfo=timezone.utc)


def _ev(ts, et, source, **kw):
    return CanonicalEvent(timestamp=ts, event_type=et, source=source, raw="x", **kw)


def _benign():
    events = [
        _ev(_at(15, 0, i), "auth", "linux-auth", source_entity="U100", src_host="WU100",
            dst_host="C2", auth_type="Kerberos", outcome="success", asset_criticality="medium")
        for i in range(12)
    ]
    events += [
        _ev(_at(15, 0, i), "network_flow", "conntrack", src_host="WU100", dst_ip="10.0.0.9",
            bytes=200 + i, duration=1.0, src_internal=True)
        for i in range(6)
    ]
    return events


def _attack():
    return [
        _ev(_at(3, 32, 16), "auth", "linux-auth", source_entity="U100", src_host="WU100",
            dst_host="C553", auth_type="NTLM", outcome="success", asset_criticality="critical"),
        _ev(_at(3, 32, 19), "process", "sysmon", source_entity="U100", src_host="C553",
            dest_entity="cmd /c whoami", asset_criticality="critical"),
        _ev(_at(3, 32, 24), "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17",
            bytes=54000, duration=900.0, src_internal=False, asset_criticality="critical"),
    ]


def _attr(inc):
    return AttributionView(technique_ids=["T1021.006"],
                           techniques=[TechniqueView(id="T1021.006", name="Remote Services", tactic="lateral-movement")],
                           explanation="x", grounded=True, predicted_next="exfiltration")


def _pipe(tmp_path, warmup=0):
    return LivePipeline(warmup_seconds=warmup, window_seconds=300, quantile=0.99,
                        attribute_fn=_attr, bus=EventBus(), state_dir=str(tmp_path))


def test_restart_does_not_relearn(tmp_path):
    async def run():
        a = _pipe(tmp_path)
        await a.ingest(_benign())   # buffer
        await a.ingest(_benign())   # fit + transition; baseline persisted
        assert a.mode == "monitoring"

        b = _pipe(tmp_path)         # fresh process, same state dir
        assert b.mode == "monitoring"  # loaded baseline — never re-entered warmup
        await b.ingest(_attack())
        assert "inc-c553" in b.incidents and b.incidents["inc-c553"].high_confidence

    asyncio.run(run())


def test_warmup_hygiene_screens_and_seeds(tmp_path):
    # screen_warmup separates contaminants deterministically
    mixed = _benign() + [
        _ev(_at(15, 0, 30), "process", "sysmon", source_entity="U9", src_host="C553",
            dest_entity="cmd /c whoami"),                                   # discovery
        _ev(_at(15, 0, 31), "network_flow", "cicids", src_host="C553",
            dst_ip="8.8.8.8", src_internal=False),                          # external
        _ev(_at(15, 0, 32), "auth", "linux-auth", source_entity="U9", src_host="X",
            dst_host="Y", outcome="failure"),                              # failed auth
    ]
    clean, suspicious = screen_warmup(mixed)
    assert len(suspicious) == 3
    assert all(e in clean for e in _benign())

    async def run():
        bus = EventBus()
        q = bus._new_queue()
        p = LivePipeline(warmup_seconds=0, window_seconds=300, quantile=0.99,
                         attribute_fn=_attr, bus=bus, state_dir=str(tmp_path))
        await p.ingest(mixed)   # buffer
        await p.ingest([])      # fit on clean only; seeded suspicious correlate
        # the seeded discovery + external flow on C553 form a high-confidence incident
        assert "inc-c553" in p.incidents and p.incidents["inc-c553"].high_confidence
        warnings = []
        while not q.empty():
            warnings.append(q.get_nowait())
        assert any(w.get("reason") == "warmup_contaminated" for w in warnings)  # 3/21 > 10%

    asyncio.run(run())


def test_reset_is_explicit_and_roundtrips(tmp_path):
    async def run():
        p = _pipe(tmp_path)
        await p.ingest(_benign())
        await p.ingest(_benign())
        assert baseline_path(tmp_path).exists()
        p.reset_baseline()
        assert not baseline_path(tmp_path).exists()
        assert p.mode == "warmup"

    asyncio.run(run())

    save_baseline(tmp_path, None, None, 0.5, 0.7)
    data = load_baseline(tmp_path)
    assert data["auth_threshold"] == 0.5 and data["net_threshold"] == 0.7
    delete_baseline(tmp_path)
    assert load_baseline(tmp_path) is None

    baseline_path(tmp_path).write_bytes(b"not a pickle")
    assert load_baseline(tmp_path) is None  # corrupt → absent
