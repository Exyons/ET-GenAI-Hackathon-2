from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator


class EventBus:
    """Tiny in-process pub/sub for SSE. Publishers never block: a full subscriber
    queue drops the event rather than raising or awaiting."""

    def __init__(self, maxsize: int = 1000) -> None:
        self.maxsize = maxsize
        self.subscribers: set[asyncio.Queue] = set()

    def _new_queue(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self.maxsize)
        self.subscribers.add(q)
        return q

    def publish(self, event: dict) -> None:
        for q in list(self.subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # drop-on-full; SSE clients tolerate gaps

    async def subscribe(self) -> AsyncIterator[dict]:
        q = self._new_queue()
        try:
            while True:
                yield await q.get()
        finally:
            self.subscribers.discard(q)
