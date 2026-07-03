from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from prahari.detect.features_auth import AuthBaseline
from prahari.schema import CanonicalEvent

# Weights emphasise the strongest lateral-movement signals: a never-before-seen
# destination and its criticality, then a rare auth mechanism (pass-the-hash),
# off-hours activity, and a new source host. Order matches AuthBaseline.featurize:
# [is_new_dest, is_new_src, auth_type_rarity, hour_novelty, dest_criticality]
_WEIGHTS = np.array([0.28, 0.14, 0.18, 0.16, 0.24])


class Sentinel:
    """Ensemble auth anomaly detector (spec §5).

    Primary signal: a learned per-entity behavioural novelty score (UEBA).
    Secondary signal: IsolationForest over the same features. The novelty score
    dominates so that multi-signal low-and-slow attacks rank above benign single-
    feature outliers, while IsolationForest adds sensitivity to subtler patterns.
    """

    def __init__(self, random_state: int = 0, novelty_weight: float = 0.7) -> None:
        self.random_state = random_state
        self.novelty_weight = novelty_weight
        self.baseline = AuthBaseline()
        self.model = IsolationForest(random_state=random_state, contamination="auto")
        self._if_min = 0.0
        self._if_max = 1.0

    def _auth_only(self, events: list[CanonicalEvent]) -> list[CanonicalEvent]:
        return [e for e in events if e.event_type == "auth"]

    def _novelty(self, event: CanonicalEvent) -> float:
        f = np.array(self.baseline.featurize(event), dtype=float)
        return float(_WEIGHTS @ f)

    def _if_raw(self, event: CanonicalEvent) -> float:
        x = np.array([self.baseline.featurize(event)], dtype=float)
        # score_samples: lower = more abnormal; negate so higher = more anomalous
        return float(-self.model.score_samples(x)[0])

    def _if_norm(self, event: CanonicalEvent) -> float:
        rng = self._if_max - self._if_min
        if rng <= 0:
            return 0.0
        return float(np.clip((self._if_raw(event) - self._if_min) / rng, 0.0, 1.0))

    def fit(self, train_events: list[CanonicalEvent]) -> "Sentinel":
        auth = self._auth_only(train_events)
        self.baseline.fit(auth)
        x = np.array([self.baseline.featurize(e) for e in auth], dtype=float)
        self.model.fit(x)
        raws = np.array([self._if_raw(e) for e in auth], dtype=float)
        self._if_min, self._if_max = float(raws.min()), float(raws.max())
        return self

    def anomaly_score(self, event: CanonicalEvent) -> float:
        return (
            self.novelty_weight * self._novelty(event)
            + (1.0 - self.novelty_weight) * self._if_norm(event)
        )

    def anomaly_scores(self, events: list[CanonicalEvent]) -> np.ndarray:
        if not events:
            return np.empty(0, dtype=float)
        x = np.array([self.baseline.featurize(e) for e in events], dtype=float)
        novelty = x @ _WEIGHTS
        raw = -self.model.score_samples(x)
        rng = self._if_max - self._if_min
        if rng > 0:
            if_norm = np.clip((raw - self._if_min) / rng, 0.0, 1.0)
        else:
            if_norm = np.zeros(len(events), dtype=float)
        return self.novelty_weight * novelty + (1.0 - self.novelty_weight) * if_norm

    def suggest_threshold(
        self, train_events: list[CanonicalEvent], quantile: float = 0.95
    ) -> float:
        auth = self._auth_only(train_events)
        scores = np.array([self.anomaly_score(e) for e in auth], dtype=float)
        return float(np.quantile(scores, quantile))

    def flag_anomalies(
        self, events: list[CanonicalEvent], threshold: float
    ) -> list[bool]:
        return [self.anomaly_score(e) >= threshold for e in events]
