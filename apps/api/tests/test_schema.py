from datetime import datetime, timezone

from prahari.schema import CanonicalEvent


def test_minimal_event_defaults():
    ev = CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 15, 32, 16, tzinfo=timezone.utc),
        event_type="auth",
        source="lanl",
        raw="151036,U342@DOM1,...",
    )
    assert ev.asset_criticality == "unknown"
    assert ev.labels == []
    assert ev.src_ip is None
    assert ev.raw.startswith("151036")


def test_labels_are_independent_per_instance():
    a = CanonicalEvent(timestamp=datetime.now(timezone.utc), event_type="auth", source="lanl", raw="x")
    b = CanonicalEvent(timestamp=datetime.now(timezone.utc), event_type="auth", source="lanl", raw="y")
    a.labels.append("redteam")
    assert b.labels == []
