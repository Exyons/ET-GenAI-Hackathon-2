from datetime import datetime, timezone

import numpy as np

from prahari.detect.network import NetworkSentinel
from prahari.detect.sentinel import Sentinel
from prahari.schema import CanonicalEvent


def _auth(user, src, dst, atype, hour, crit="unknown"):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, hour, tzinfo=timezone.utc),
        event_type="auth", source_entity=user, src_host=src, dst_host=dst,
        auth_type=atype, asset_criticality=crit, source="lanl", raw="x",
    )


def _flow(nbytes, duration):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 15, tzinfo=timezone.utc),
        event_type="network_flow", bytes=nbytes, duration=duration, source="cicids", raw="x",
    )


def test_sentinel_batch_matches_single():
    train = [_auth("U100", "C1", "C2", "Kerberos", 15) for _ in range(20)]
    s = Sentinel(random_state=0).fit(train)
    probe = train + [_auth("U100", "C1", "C553", "NTLM", 3, crit="critical")]
    single = np.array([s.anomaly_score(e) for e in probe])
    batch = s.anomaly_scores(probe)
    assert np.allclose(single, batch)


def test_network_batch_matches_single():
    rng = np.random.default_rng(0)
    train = [_flow(int(b), float(d)) for b, d in zip(rng.normal(220, 15, 50), rng.normal(1100, 80, 50))]
    n = NetworkSentinel(random_state=0).fit(train)
    probe = train + [_flow(54000, 900000)]
    single = np.array([n.anomaly_score(e) for e in probe])
    batch = n.anomaly_scores(probe)
    assert np.allclose(single, batch)
