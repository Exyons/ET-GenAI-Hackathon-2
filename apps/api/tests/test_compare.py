from datetime import datetime, timezone

from prahari.detect.compare import compare_detectors
from prahari.schema import CanonicalEvent


def _auth(user, src, dst, atype, hour, crit="unknown", labels=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, hour, 0, 0, tzinfo=timezone.utc),
        event_type="auth",
        source_entity=user,
        src_host=src,
        dst_host=dst,
        auth_type=atype,
        asset_criticality=crit,
        source="lanl",
        labels=labels or [],
        raw="x",
    )


def _benign(n, start=0):
    users = ["U100", "U200", "U300"]
    dests = {"U100": ["C1", "C2"], "U200": ["C3", "C4"], "U300": ["C5", "C6"]}
    hours = [9, 13, 15, 17]
    out = []
    for i in range(start, start + n):
        u = users[i % 3]
        dst = dests[u][i % 2]
        atype = "NTLM" if i % 7 == 0 else "Kerberos"
        crit = "medium" if i % 2 == 0 else "low"
        out.append(_auth(u, f"W{u}", dst, atype, hours[i % 4], crit=crit))
    return out


def _redteam_pair():
    return [
        _auth("U100", "WU100", "C553", "NTLM", 3, crit="critical", labels=["redteam"]),
        _auth("U100", "WU100", "C777", "NTLM", 2, crit="high", labels=["redteam"]),
    ]


def test_sentinel_beats_signature_on_lowandslow():
    train = _benign(30)
    test = _benign(20, start=100) + _redteam_pair()

    results = compare_detectors(train, test, bad_ips={"203.0.113.9"}, quantile=0.95)

    # signature is blind to behavioural low-and-slow auth
    assert results["signature"].recall == 0.0
    # Sentinel catches the red-team lateral movement
    assert results["sentinel"].recall >= 0.5
    assert results["sentinel"].recall > results["signature"].recall
    # and keeps false positives on benign traffic low
    assert results["sentinel"].fpr <= 0.2
