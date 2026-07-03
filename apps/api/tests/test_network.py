from datetime import datetime, timezone

import numpy as np

from prahari.detect.network import NetworkSentinel
from prahari.schema import CanonicalEvent


def _flow(nbytes, duration, labels=None):
    return CanonicalEvent(
        timestamp=datetime(2017, 7, 5, 15, 32, tzinfo=timezone.utc),
        event_type="network_flow",
        bytes=nbytes,
        duration=duration,
        source="cicids",
        labels=labels or [],
        raw="x",
    )


def _benign_flows(n=100):
    # benign flows: a 2D blob (bytes ~220, duration ~1100) with realistic spread
    rng = np.random.default_rng(0)
    b = rng.normal(220, 15, n)
    d = rng.normal(1100, 80, n)
    return [_flow(int(bi), float(di)) for bi, di in zip(b, d)]


def test_attack_flow_is_most_anomalous():
    train = _benign_flows()
    net = NetworkSentinel(random_state=0).fit(train)

    attack = _flow(54000, 900000, labels=["attack", "DDoS"])
    population = train + [attack]
    scores = [net.anomaly_score(e) for e in population]

    # the DDoS flow is the single most anomalous
    assert scores.index(max(scores)) == len(population) - 1


def test_attack_flagged_above_benign_threshold():
    train = _benign_flows()
    net = NetworkSentinel(random_state=0).fit(train)

    benign_scores = np.array([net.anomaly_score(e) for e in train])
    threshold = float(np.quantile(benign_scores, 0.95))
    attack = _flow(54000, 900000, labels=["attack", "DDoS"])

    assert net.anomaly_score(attack) > threshold
