from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable

from prahari.schema import CanonicalEvent

FEATURE_NAMES = [
    "is_new_dest",
    "is_new_src",
    "auth_type_rarity",
    "hour_novelty",
    "dest_criticality",
]

_CRIT_NUM = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0, "unknown": 0.0}


class AuthBaseline:
    def __init__(self) -> None:
        self.user_dests: dict[str, set[str]] = defaultdict(set)
        self.user_srcs: dict[str, set[str]] = defaultdict(set)
        self.user_authtype: dict[str, Counter] = defaultdict(Counter)
        self.user_hours: dict[str, set[int]] = defaultdict(set)

    def fit(self, events: Iterable[CanonicalEvent]) -> "AuthBaseline":
        for e in events:
            if e.event_type != "auth":
                continue
            u = e.source_entity or "?"
            if e.dst_host:
                self.user_dests[u].add(e.dst_host)
            if e.src_host:
                self.user_srcs[u].add(e.src_host)
            if e.auth_type:
                self.user_authtype[u][e.auth_type] += 1
            self.user_hours[u].add(e.timestamp.hour)
        return self

    def featurize(self, e: CanonicalEvent) -> list[float]:
        u = e.source_entity or "?"
        is_new_dest = 0.0 if e.dst_host in self.user_dests.get(u, set()) else 1.0
        is_new_src = 0.0 if e.src_host in self.user_srcs.get(u, set()) else 1.0
        counts = self.user_authtype.get(u, Counter())
        total = sum(counts.values())
        atype_rarity = 1.0 - (counts.get(e.auth_type, 0) / total) if total else 1.0
        hour_novelty = 0.0 if e.timestamp.hour in self.user_hours.get(u, set()) else 1.0
        dest_crit = _CRIT_NUM.get(e.asset_criticality, 0.0)
        return [is_new_dest, is_new_src, atype_rarity, hour_novelty, dest_crit]
