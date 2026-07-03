from __future__ import annotations

from prahari.correlate.correlator import correlate
from prahari.correlate.incident import Incident
from prahari.correlate.killchain import actor_of
from prahari.schema import CanonicalEvent


def triage(
    flagged_events: list[CanonicalEvent],
    window_seconds: float = 600,
    min_events: int = 3,
) -> list[Incident]:
    incidents = correlate(flagged_events, key_fn=actor_of, window_seconds=window_seconds)
    kept = [inc for inc in incidents if len(inc.events) >= min_events]
    kept.sort(key=lambda i: i.compound_score, reverse=True)
    return kept
