from datetime import datetime, timezone

from prahari.schema import CanonicalEvent
from prahari.stream import merge_ordered


def _ev(sec, source):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 15, 32, sec, tzinfo=timezone.utc),
        event_type="auth",
        source=source,
        raw=f"{source}-{sec}",
    )


def test_merge_orders_by_timestamp_across_sources():
    a = [_ev(24, "cicids"), _ev(16, "lanl")]
    b = [_ev(19, "sysmon")]
    merged = merge_ordered(a, b)
    assert [e.timestamp.second for e in merged] == [16, 19, 24]
    assert [e.source for e in merged] == ["lanl", "sysmon", "cicids"]


def test_merge_empty():
    assert merge_ordered([], []) == []
