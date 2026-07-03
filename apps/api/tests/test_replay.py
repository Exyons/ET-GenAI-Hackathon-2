from datetime import datetime, timezone

from prahari.replay import replay
from prahari.schema import CanonicalEvent


def _ev(sec):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 15, 32, sec, tzinfo=timezone.utc),
        event_type="auth",
        source="lanl",
        raw=str(sec),
    )


def test_replay_yields_in_order_and_paces_by_speed():
    events = [_ev(0), _ev(10), _ev(40)]  # gaps 10s, 30s
    slept: list[float] = []
    out = list(replay(events, speed=100.0, sleep=slept.append))

    assert [e.timestamp.second for e in out] == [0, 10, 40]
    # first event no sleep; then 10/100 and 30/100
    assert slept == [0.1, 0.3]


def test_replay_empty():
    assert list(replay([], sleep=lambda _s: None)) == []
