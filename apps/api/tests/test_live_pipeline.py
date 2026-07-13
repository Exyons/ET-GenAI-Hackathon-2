import asyncio
from datetime import datetime, timezone

from prahari.api.models import AttributionView, TechniqueView
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


def _fake_attr(inc):
    return AttributionView(
        technique_ids=["T1021.006"],
        techniques=[TechniqueView(id="T1021.006", name="Remote Services", tactic="lateral-movement")],
        explanation="fused lateral movement", grounded=True, predicted_next="exfiltration",
    )


def test_live_pipeline_detects_and_attributes(tmp_path):
    async def run():
        bus = EventBus()
        q = bus._new_queue()
        p = LivePipeline(warmup_seconds=0, window_seconds=300, quantile=0.99,
                         attribute_fn=_fake_attr, bus=bus, state_dir=str(tmp_path))
        await p.ingest(_benign())      # buffered
        await p.ingest(_attack())      # fit on benign, monitor attack

        assert "inc-c553" in p.incidents
        assert p.incidents["inc-c553"].high_confidence is True
        assert "inc-c553" in p.attributions
        assert p.attributions["inc-c553"].technique_ids == ["T1021.006"]

        seen = []
        while not q.empty():
            seen.append(q.get_nowait())
        assert any(e["type"] == "incident" and e.get("id") == "inc-c553" for e in seen)
        assert any(e["type"] == "attribution" and e.get("id") == "inc-c553" for e in seen)

    asyncio.run(run())


def test_tick_transitions_without_new_ingest(tmp_path):
    # a burst then silence: the buffer holds warmup + attack; tick() flips the mode
    # on time even though no further /api/ingest arrives.
    async def run():
        p = LivePipeline(warmup_seconds=0, window_seconds=300, quantile=0.99,
                         attribute_fn=_fake_attr, bus=EventBus(), state_dir=str(tmp_path))
        await p.ingest(_benign() + _attack())   # everything buffered (single batch)
        assert p.mode == "warmup"
        await p.tick()                            # time-driven transition
        assert p.mode == "monitoring"
        # the attack's discovery + external flow were screened out and correlate immediately
        assert "inc-c553" in p.incidents and p.incidents["inc-c553"].high_confidence

    asyncio.run(run())
