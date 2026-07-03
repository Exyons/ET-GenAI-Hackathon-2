from datetime import datetime, timezone

from prahari.detect.signature import SignatureBaseline
from prahari.schema import CanonicalEvent


def _auth(dst, labels=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 3, 0, tzinfo=timezone.utc),
        event_type="auth",
        source_entity="U342",
        src_host="C1115",
        dst_host=dst,
        auth_type="NTLM",
        source="lanl",
        labels=labels or [],
        raw="x",
    )


def _flow(dst_ip, labels=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 15, 32, tzinfo=timezone.utc),
        event_type="network_flow",
        dst_ip=dst_ip,
        source="cicids",
        labels=labels or [],
        raw="x",
    )


def test_signature_silent_on_lowandslow_auth():
    sig = SignatureBaseline(bad_ips={"203.0.113.9"})
    # the red-team lateral movement is an auth event with no known bad indicator
    assert sig.flag(_auth("C553", labels=["redteam"])) is False


def test_signature_catches_known_bad_ip():
    sig = SignatureBaseline(bad_ips={"203.0.113.9"})
    assert sig.flag(_flow("203.0.113.9", labels=["attack"])) is True
    assert sig.flag(_flow("52.84.23.17")) is False
