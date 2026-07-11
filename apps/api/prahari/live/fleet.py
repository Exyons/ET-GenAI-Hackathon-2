from __future__ import annotations

import time
from collections import Counter, deque

from prahari.api.serialize import event_view
from prahari.correlate.killchain import target_of
from prahari.schema import CanonicalEvent

BUCKET_SECONDS = 10
BUCKET_SPAN = 36           # 6 minutes of throughput history
TAPE_SIZE = 80
RATE_WINDOW_S = 60.0


def host_os(source: str) -> str:
    if source.startswith("windows") or source == "sysmon":
        return "windows"
    if source.startswith("linux") or source == "conntrack":
        return "linux"
    return "unknown"


class Fleet:
    """Bookkeeping behind the command deck: which hosts are reporting, at what
    rate, plus a tape of the latest events. Pure counters — no ML, no I/O."""

    def __init__(self, clock=time.time) -> None:
        self._clock = clock
        self.hosts: dict[str, dict] = {}
        self.by_type: Counter = Counter()
        self._buckets: dict[int, Counter] = {}
        self.tape: deque = deque(maxlen=TAPE_SIZE)

    def observe(self, events: list[CanonicalEvent], flags: list[bool]) -> list[dict]:
        """Record one ingest batch; returns the tape entries it produced."""
        now = self._clock()
        bucket = int(now // BUCKET_SECONDS) * BUCKET_SECONDS
        counts = self._buckets.setdefault(bucket, Counter())
        added: list[dict] = []
        for e, flagged in zip(events, flags):
            host = target_of(e) or e.src_host or "unknown"
            h = self.hosts.setdefault(host, {
                "os": "unknown", "sources": set(), "by_type": Counter(),
                "seen": deque(maxlen=2000),
            })
            if h["os"] == "unknown":
                h["os"] = host_os(e.source)
            h["sources"].add(e.source)
            h["by_type"][e.event_type] += 1
            h["seen"].append(now)
            self.by_type[e.event_type] += 1
            counts[e.event_type] += 1
            entry = {**event_view(e).model_dump(mode="json"), "host": host, "flagged": flagged}
            self.tape.append(entry)
            added.append(entry)
        self._prune(bucket)
        return added

    def _prune(self, current_bucket: int) -> None:
        floor = current_bucket - BUCKET_SPAN * BUCKET_SECONDS
        for k in [k for k in self._buckets if k < floor]:
            del self._buckets[k]

    def snapshot(self) -> dict:
        now = self._clock()
        current = int(now // BUCKET_SECONDS) * BUCKET_SECONDS
        series = []
        for i in range(BUCKET_SPAN - 1, -1, -1):
            start = current - i * BUCKET_SECONDS
            c = self._buckets.get(start, Counter())
            series.append({"t": start, "auth": c["auth"], "process": c["process"],
                           "network_flow": c["network_flow"]})
        hosts = []
        for name, h in self.hosts.items():
            epm = sum(1 for t in h["seen"] if t >= now - RATE_WINDOW_S)
            hosts.append({
                "host": name, "os": h["os"], "sources": sorted(h["sources"]),
                "by_type": dict(h["by_type"]), "total": sum(h["by_type"].values()),
                "epm": epm,
                "last_seen_s": round(now - h["seen"][-1], 1) if h["seen"] else None,
            })
        hosts.sort(key=lambda x: (x["last_seen_s"] is None, x["last_seen_s"]))
        last_minute = sum(b["auth"] + b["process"] + b["network_flow"] for b in series[-6:])
        return {"hosts": hosts, "by_type": dict(self.by_type),
                "series": series, "rate_epm": last_minute}
