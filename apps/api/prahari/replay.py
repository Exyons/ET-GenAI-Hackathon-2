from __future__ import annotations

import time
from collections.abc import Callable, Iterator

from prahari.schema import CanonicalEvent


def replay(
    events: list[CanonicalEvent],
    speed: float = 100.0,
    sleep: Callable[[float], None] = time.sleep,
) -> Iterator[CanonicalEvent]:
    prev = None
    for ev in events:
        if prev is not None:
            gap = (ev.timestamp - prev).total_seconds() / speed
            if gap > 0:
                sleep(gap)
        prev = ev.timestamp
        yield ev
