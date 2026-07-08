from __future__ import annotations

import time
from collections import deque
from datetime import timedelta

import numpy as np

from prahari.api.demo import incident_id
from prahari.api.serialize import to_summary
from prahari.correlate.correlator import correlate
from prahari.correlate.incident import Incident
from prahari.correlate.killchain import killchain_phase, target_of
from prahari.detect.network import NetworkSentinel
from prahari.detect.sentinel import Sentinel
from prahari.live.baseline import (
    delete_baseline,
    load_baseline,
    save_baseline,
    screen_warmup,
)


class LivePipeline:
    def __init__(self, warmup_seconds, window_seconds, quantile, attribute_fn, bus, state_dir):
        self.warmup_seconds = warmup_seconds
        self.window_seconds = window_seconds
        self.quantile = quantile
        self.attribute_fn = attribute_fn
        self.bus = bus
        self.state_dir = state_dir

        self.mode = "warmup"
        self._t0: float | None = None
        self.warmup_events: list = []
        self.events_seen = 0
        self.auth_sentinel: Sentinel | None = None
        self.net_sentinel: NetworkSentinel | None = None
        self.auth_threshold: float | None = None
        self.net_threshold: float | None = None
        self.recent: deque = deque()
        self.incidents: dict[str, Incident] = {}
        self.attributions: dict = {}
        self._high_conf: set[str] = set()

        # Poisoning defense #1: a restart never re-learns — load the persisted baseline
        # and start straight in MONITORING. Re-baselining is an explicit operator action.
        data = load_baseline(state_dir)
        if data:
            self.auth_sentinel = data["auth_sentinel"]
            self.net_sentinel = data["net_sentinel"]
            self.auth_threshold = data["auth_threshold"]
            self.net_threshold = data["net_threshold"]
            self.mode = "monitoring"

    # ---- ingest / state machine ----
    async def ingest(self, events: list) -> None:
        self.events_seen += len(events)
        pairs: list[tuple[str, Incident]] = []
        if self.mode == "warmup":
            if self._t0 is None:
                self._t0 = time.monotonic()
            if (time.monotonic() - self._t0) >= self.warmup_seconds and self.warmup_events:
                pairs += self._fit_and_transition()
                pairs += self._monitor(events)
            else:
                self.warmup_events.extend(events)
        else:
            pairs += self._monitor(events)
        for iid, inc in pairs:
            await self._attribute(iid, inc)

    def _fit_and_transition(self) -> list[tuple[str, Incident]]:
        buf = self.warmup_events
        clean, suspicious = screen_warmup(buf)  # poisoning defense #2
        auth_clean = [e for e in clean if e.event_type == "auth"]
        flow_clean = [e for e in clean if e.event_type == "network_flow"]
        if auth_clean:
            self.auth_sentinel = Sentinel(random_state=0).fit(clean)
            self.auth_threshold = self.auth_sentinel.suggest_threshold(clean, quantile=self.quantile)
        if flow_clean:
            self.net_sentinel = NetworkSentinel(random_state=0).fit(clean)
            scores = self.net_sentinel.anomaly_scores(flow_clean)
            self.net_threshold = float(np.quantile(scores, self.quantile))
        for e in suspicious:  # seed so they correlate immediately, not absorbed
            self.recent.append(e)
        if buf and len(suspicious) / len(buf) > 0.10:
            self.bus.publish({
                "type": "warning", "reason": "warmup_contaminated",
                "suspicious": len(suspicious), "total": len(buf),
            })
        save_baseline(self.state_dir, self.auth_sentinel, self.net_sentinel,
                      self.auth_threshold, self.net_threshold)
        self.mode = "monitoring"
        self.warmup_events = []
        return self._correlate()

    def _monitor(self, events: list) -> list[tuple[str, Incident]]:
        for e in events:
            if self._is_flagged(e):
                self.recent.append(e)
        self._prune()
        return self._correlate()

    # ---- detection ----
    def _host_has_flag(self, host: str | None) -> bool:
        return host is not None and any(target_of(x) == host for x in self.recent)

    def _is_flagged(self, e) -> bool:
        if e.event_type == "auth" and self.auth_sentinel is not None and self.auth_threshold is not None:
            if self.auth_sentinel.anomaly_score(e) >= self.auth_threshold:
                return True
        if e.event_type == "network_flow" and self.net_sentinel is not None and self.net_threshold is not None:
            if self.net_sentinel.anomaly_score(e) >= self.net_threshold:
                return True
        if e.event_type == "process":
            if killchain_phase(e) == "discovery":
                return True
            if self._host_has_flag(target_of(e)):
                return True
        # poisoning defense #3: model-independent guardrail — external flow with corroboration
        if e.event_type == "network_flow" and e.src_internal is False and self._host_has_flag(target_of(e)):
            return True
        return False

    def _prune(self) -> None:
        if not self.recent:
            return
        latest = max(e.timestamp for e in self.recent)
        cutoff = latest - timedelta(seconds=2 * self.window_seconds)
        self.recent = deque(e for e in self.recent if e.timestamp >= cutoff)

    def _correlate(self) -> list[tuple[str, Incident]]:
        new_hc: list[tuple[str, Incident]] = []
        for inc in correlate(list(self.recent), key_fn=target_of, window_seconds=self.window_seconds):
            iid = incident_id(inc)
            self.incidents[iid] = inc
            if inc.high_confidence and iid not in self._high_conf:
                self._high_conf.add(iid)
                self.bus.publish({"type": "incident", **to_summary(inc).model_dump()})
                new_hc.append((iid, inc))
        return new_hc

    async def _attribute(self, iid: str, inc: Incident) -> None:
        try:
            view = self.attribute_fn(inc)
            self.attributions[iid] = view
            self.bus.publish({"type": "attribution", "id": iid, **view.model_dump()})
        except Exception:
            pass  # attribution failure must never break the pipeline

    # ---- operator / query ----
    def reset_baseline(self) -> None:
        delete_baseline(self.state_dir)
        self.auth_sentinel = self.net_sentinel = None
        self.auth_threshold = self.net_threshold = None
        self.warmup_events = []
        self._t0 = None
        self.recent.clear()
        self.mode = "warmup"

    def status(self) -> dict:
        if self.mode == "warmup":
            remaining = self.warmup_seconds - (time.monotonic() - self._t0) if self._t0 else self.warmup_seconds
            remaining = max(0.0, remaining)
        else:
            remaining = 0.0
        return {
            "mode": self.mode,
            "events_seen": self.events_seen,
            "warmup_remaining_s": round(remaining, 1),
            "incident_count": len(self.incidents),
        }
