from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable

from prahari.correlate.incident import Incident
from prahari.correlate.killchain import actor_of, target_of  # noqa: F401 (re-export)
from prahari.schema import CanonicalEvent


def correlate(
    events: list[CanonicalEvent],
    key_fn: Callable[[CanonicalEvent], str | None],
    window_seconds: float,
) -> list[Incident]:
    groups: dict[str, list[CanonicalEvent]] = defaultdict(list)
    for e in events:
        k = key_fn(e)
        if k is not None:
            groups[k].append(e)

    incidents: list[Incident] = []
    for key, evs in groups.items():
        evs.sort(key=lambda e: e.timestamp)
        cluster = [evs[0]]
        for e in evs[1:]:
            gap = (e.timestamp - cluster[-1].timestamp).total_seconds()
            if gap <= window_seconds:
                cluster.append(e)
            else:
                incidents.append(Incident(entity=key, events=cluster))
                cluster = [e]
        incidents.append(Incident(entity=key, events=cluster))

    incidents.sort(key=lambda i: i.compound_score, reverse=True)
    return incidents
