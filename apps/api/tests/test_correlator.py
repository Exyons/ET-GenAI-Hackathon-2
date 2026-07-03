from datetime import datetime, timedelta, timezone

from prahari.correlate.correlator import correlate
from prahari.correlate.killchain import actor_of, target_of
from prahari.schema import CanonicalEvent

T0 = datetime(2017, 7, 5, 15, 0, 0, tzinfo=timezone.utc)


def _ev(offset_s, event_type, source, **kw):
    base = dict(timestamp=T0 + timedelta(seconds=offset_s),
                event_type=event_type, source=source, raw="x")
    base.update(kw)
    return CanonicalEvent(**base)


def test_time_gap_splits_incidents():
    events = [
        _ev(0, "auth", "lanl", source_entity="U1", dst_host="C2"),
        _ev(30, "auth", "lanl", source_entity="U1", dst_host="C3"),
        _ev(5000, "auth", "lanl", source_entity="U1", dst_host="C4"),  # far later
    ]
    incs = correlate(events, key_fn=actor_of, window_seconds=300)
    # U1 splits into two incidents: [0,30] and [5000]
    sizes = sorted(len(i.events) for i in incs)
    assert sizes == [1, 2]


def test_fused_timeline_by_target_is_one_high_confidence_incident():
    events = [
        _ev(16, "auth", "lanl", source_entity="U342", dst_host="C553",
            asset_criticality="critical", labels=["redteam"]),
        _ev(19, "process", "otrf", source_entity="U342", src_host="C553",
            dest_entity="cmd /c whoami"),
        _ev(24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17"),
    ]
    incs = correlate(events, key_fn=target_of, window_seconds=300)
    assert len(incs) == 1
    inc = incs[0]
    assert inc.entity == "C553"
    assert inc.high_confidence is True
    assert len(inc.events) == 3
