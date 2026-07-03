from __future__ import annotations

from collections.abc import Iterable

from prahari.schema import CanonicalEvent


def merge_ordered(*streams: Iterable[CanonicalEvent]) -> list[CanonicalEvent]:
    events = [e for stream in streams for e in stream]
    events.sort(key=lambda e: e.timestamp)  # stable
    return events
