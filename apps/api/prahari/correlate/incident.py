from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from prahari.correlate.killchain import killchain_phase
from prahari.schema import CanonicalEvent

_CRIT_NUM = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0, "unknown": 0.0}
_TRUE_LABELS = {"redteam", "attack"}


@dataclass
class Incident:
    entity: str
    events: list[CanonicalEvent]

    @property
    def start(self) -> datetime:
        return min(e.timestamp for e in self.events)

    @property
    def end(self) -> datetime:
        return max(e.timestamp for e in self.events)

    @property
    def phases(self) -> set[str]:
        return {killchain_phase(e) for e in self.events}

    @property
    def sources(self) -> set[str]:
        return {e.source for e in self.events}

    @property
    def is_true_positive(self) -> bool:
        return any(_TRUE_LABELS & set(e.labels) for e in self.events)

    @property
    def _max_criticality(self) -> float:
        return max(_CRIT_NUM.get(e.asset_criticality, 0.0) for e in self.events)

    @property
    def compound_score(self) -> float:
        source_div = min(len(self.sources) - 1, 2) / 2  # 0..1 (2+ sources = max)
        phase_div = min(len(self.phases) - 1, 2) / 2      # 0..1 (3+ phases = max)
        volume = min(len(self.events), 5) / 5             # 0..1 (5+ events = max)
        crit = self._max_criticality
        score = 0.35 * source_div + 0.30 * phase_div + 0.15 * volume + 0.20 * crit
        return round(score, 4)

    @property
    def high_confidence(self) -> bool:
        return len(self.sources) >= 2 and len(self.phases) >= 2

    def timeline(self) -> list[CanonicalEvent]:
        return sorted(self.events, key=lambda e: e.timestamp)
