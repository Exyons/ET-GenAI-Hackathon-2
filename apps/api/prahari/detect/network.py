from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from prahari.schema import CanonicalEvent


def _features(e: CanonicalEvent) -> list[float]:
    return [float(e.bytes or 0), float(e.duration or 0.0)]


class NetworkSentinel:
    def __init__(self, random_state: int = 0) -> None:
        self.scaler = StandardScaler()
        self.model = IsolationForest(random_state=random_state, contamination="auto")

    def fit(self, train_events: list[CanonicalEvent]) -> "NetworkSentinel":
        flows = [e for e in train_events if e.event_type == "network_flow"]
        x = np.array([_features(e) for e in flows], dtype=float)
        xs = self.scaler.fit_transform(x)
        self.model.fit(xs)
        return self

    def anomaly_score(self, event: CanonicalEvent) -> float:
        x = np.array([_features(event)], dtype=float)
        xs = self.scaler.transform(x)
        return float(-self.model.score_samples(xs)[0])
