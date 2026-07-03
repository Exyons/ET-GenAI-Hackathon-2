from datetime import datetime, timedelta, timezone

from prahari.correlate.triage import triage
from prahari.schema import CanonicalEvent

T0 = datetime(2017, 7, 5, 15, 0, 0, tzinfo=timezone.utc)


def _auth(offset_s, user, dst, labels=None):
    return CanonicalEvent(
        timestamp=T0 + timedelta(seconds=offset_s),
        event_type="auth", source_entity=user, src_host="W" + user, dst_host=dst,
        auth_type="NTLM", source="lanl", labels=labels or [], raw="x",
    )


def test_triage_recovers_burst_and_drops_scattered_fps():
    # red-team actor U342: a burst of 4 anomalous lateral moves within window
    flagged = [
        _auth(0, "U342", "C500", labels=["redteam"]),
        _auth(20, "U342", "C501", labels=["redteam"]),
        _auth(40, "U342", "C502", labels=["redteam"]),
        _auth(60, "U342", "C503", labels=["redteam"]),
    ]
    # 15 scattered benign false positives: different users, one stray flag each
    flagged += [_auth(100 + 500 * i, f"B{i}", "C9", labels=[]) for i in range(15)]

    incidents = triage(flagged, window_seconds=600, min_events=3)

    # 19 per-event flags collapse to exactly one surviving incident: the real burst
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.entity == "U342"
    assert inc.is_true_positive is True
    assert len(inc.events) == 4
