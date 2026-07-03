from datetime import datetime, timezone

from prahari.enrich import enrich, is_internal
from prahari.schema import CanonicalEvent


def _auth(dst_host, src_ip=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, tzinfo=timezone.utc),
        event_type="auth",
        dst_host=dst_host,
        src_ip=src_ip,
        source="lanl",
        raw="x",
    )


def test_is_internal():
    assert is_internal("10.0.0.9") is True
    assert is_internal("192.168.1.1") is True
    assert is_internal("52.84.23.17") is False
    assert is_internal(None) is None


def test_enrich_sets_criticality_and_internal():
    ev = enrich(_auth("C553", src_ip="10.0.0.9"))
    assert ev.asset_criticality == "critical"
    assert ev.src_internal is True


def test_enrich_unknown_host_stays_unknown():
    ev = enrich(_auth("C9999"))
    assert ev.asset_criticality == "unknown"
