from __future__ import annotations

import time
from collections import Counter, deque
from datetime import datetime, timedelta, timezone

import numpy as np

from prahari.api.demo import incident_id
from prahari.api.serialize import event_view, to_summary
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
from prahari.live.fleet import Fleet


def norm_cmd(cmd: str) -> str:
    return " ".join(cmd.split()).lower()[:200]


# a sentinel fit on a handful of events produces a meaningless threshold that
# flags everything; below this many clean training events the detector stays off
MIN_FIT_EVENTS = 12

ATTR_RETRY_SECONDS = 60.0


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
        self.fleet = Fleet()
        self.process_baseline: set[str] = set()
        self._seen_flags: dict = {}           # (reason, host, signature) -> last flagged ts
        self._attr_retry_t = 0.0
        self.stats: Counter = Counter()
        self.activity: deque = deque(maxlen=60)

        # Poisoning defense #1: a restart never re-learns — load the persisted baseline
        # and start straight in MONITORING. Re-baselining is an explicit operator action.
        data = load_baseline(state_dir)
        if data:
            self.auth_sentinel = data["auth_sentinel"]
            self.net_sentinel = data["net_sentinel"]
            self.auth_threshold = data["auth_threshold"]
            self.net_threshold = data["net_threshold"]
            self.process_baseline = data.get("process_baseline") or set()
            self.mode = "monitoring"
            self._log("baseline", "persisted baseline loaded — monitoring (restart never re-learns)")

    def _log(self, stage: str, msg: str) -> None:
        self.activity.append({"t": datetime.now(timezone.utc).isoformat(),
                              "stage": stage, "msg": msg})

    # ---- ingest / state machine ----
    async def ingest(self, events: list) -> None:
        self.events_seen += len(events)
        if events:
            self.stats["batches"] += 1
            self.stats["events"] += len(events)
        pairs: list[tuple[str, Incident]] = []
        tape: list[dict] = []
        if self.mode == "warmup":
            if self._t0 is None:
                self._t0 = time.monotonic()
            if (time.monotonic() - self._t0) >= self.warmup_seconds and self.warmup_events:
                pairs += self._fit_and_transition()
                pairs += self._monitor(events, tape)
            else:
                self.warmup_events.extend(events)
                tape += self.fleet.observe(events, [False] * len(events))
        else:
            pairs += self._monitor(events, tape)
        if tape:
            self.bus.publish({"type": "telemetry", "events": tape[-12:]})
        for iid, inc in pairs:
            await self._attribute(iid, inc)

    async def tick(self) -> None:
        # time-driven backstop: transition when the warmup window elapses even if no
        # new events arrive (e.g. a short demo that sends a burst then stops).
        if (self.mode == "warmup" and self._t0 is not None and self.warmup_events
                and (time.monotonic() - self._t0) >= self.warmup_seconds):
            for iid, inc in self._fit_and_transition():
                await self._attribute(iid, inc)
        # retry attribution for high-conf incidents that still lack it — covers the
        # LLM coming up after the incident was promoted
        missing = [iid for iid in self._high_conf if iid not in self.attributions]
        if missing and (time.monotonic() - self._attr_retry_t) >= ATTR_RETRY_SECONDS:
            self._attr_retry_t = time.monotonic()
            for iid in missing:
                inc = self.incidents.get(iid)
                if inc is not None:
                    await self._attribute(iid, inc)

    def _fit_and_transition(self) -> list[tuple[str, Incident]]:
        buf = self.warmup_events
        clean, suspicious = screen_warmup(buf)  # poisoning defense #2
        auth_clean = [e for e in clean if e.event_type == "auth"]
        flow_clean = [e for e in clean if e.event_type == "network_flow"]
        if len(auth_clean) >= MIN_FIT_EVENTS:
            self.auth_sentinel = Sentinel(random_state=0).fit(clean)
            self.auth_threshold = self.auth_sentinel.suggest_threshold(clean, quantile=self.quantile)
        if len(flow_clean) >= MIN_FIT_EVENTS:
            self.net_sentinel = NetworkSentinel(random_state=0).fit(clean)
            scores = self.net_sentinel.anomaly_scores(flow_clean)
            self.net_threshold = float(np.quantile(scores, self.quantile))
        # process baseline: commands seen (clean) during warmup are this fleet's normal —
        # system services re-running them later are never flagged as discovery
        self.process_baseline = {norm_cmd(e.dest_entity) for e in clean
                                 if e.event_type == "process" and e.dest_entity}
        for e in suspicious:  # seed so they correlate immediately, not absorbed
            self.recent.append(e)
        self.stats["screened"] += len(suspicious)
        if buf and len(suspicious) / len(buf) > 0.10:
            self.bus.publish({
                "type": "warning", "reason": "warmup_contaminated",
                "suspicious": len(suspicious), "total": len(buf),
            })
            self._log("baseline", f"⚠ warmup contaminated — {len(suspicious)}/{len(buf)} "
                                  "events screened out and queued for correlation")
        save_baseline(self.state_dir, self.auth_sentinel, self.net_sentinel,
                      self.auth_threshold, self.net_threshold, self.process_baseline)
        self.mode = "monitoring"
        self.warmup_events = []

        def _fit_note(model, n: int) -> str:
            return f"fit on {n}" if model is not None else f"off ({n} < {MIN_FIT_EVENTS} events)"
        self._log("baseline", f"baseline frozen — auth model {_fit_note(self.auth_sentinel, len(auth_clean))} · "
                              f"network model {_fit_note(self.net_sentinel, len(flow_clean))} · "
                              f"screened {len(suspicious)} · learned "
                              f"{len(self.process_baseline)} normal process commands")
        return self._correlate()

    def _monitor(self, events: list, tape: list[dict] | None = None) -> list[tuple[str, Incident]]:
        flags = []
        for e in events:
            reason = self._flag_reason(e)
            if reason:
                self.recent.append(e)
                self.stats[reason] += 1
                host = target_of(e) or e.src_host or "?"
                self._log("sentinel", f"⚑ {reason.replace('_', ' ')} · {host} · "
                                      f"{event_view(e).detail[:70]}")
            flags.append(reason is not None)
        if tape is not None:
            tape += self.fleet.observe(events, flags)
        self._prune()
        return self._correlate()

    # ---- detection ----
    def _host_has_flag(self, host: str | None) -> bool:
        return host is not None and any(target_of(x) == host for x in self.recent)

    def _host_has_anomaly(self, host: str | None) -> bool:
        # non-process evidence only — a flagged process must never corroborate more
        # processes, or one discovery command cascades into flagging everything
        return host is not None and any(
            target_of(x) == host and x.event_type != "process" for x in self.recent)

    def _dedup(self, reason: str, host: str | None, signature: str, ts) -> bool:
        """Each distinct behavior (per host) is reported once per window; while it
        keeps repeating the suppression keeps refreshing — steady noise stays quiet."""
        key = (reason, host, signature)
        last = self._seen_flags.get(key)
        self._seen_flags[key] = ts
        return last is None or (ts - last).total_seconds() >= self.window_seconds

    def _flag_reason(self, e) -> str | None:
        host, ts = target_of(e), e.timestamp
        # strictly greater: with a homogeneous baseline the threshold equals the
        # normal score, and >= would flag every ordinary event as anomalous
        if e.event_type == "auth" and self.auth_sentinel is not None and self.auth_threshold is not None:
            if self.auth_sentinel.anomaly_score(e) > self.auth_threshold:
                sig = f"{e.source_entity}|{e.src_ip}|{e.auth_type}|{e.outcome}"
                return "auth_anomaly" if self._dedup("auth_anomaly", host, sig, ts) else None
        if e.event_type == "network_flow":
            dst = e.dst_ip or e.dst_host or "?"
            if (self.net_sentinel is not None and self.net_threshold is not None
                    and self.net_sentinel.anomaly_score(e) > self.net_threshold):
                return "net_anomaly" if self._dedup("net_anomaly", host, dst, ts) else None
            # poisoning defense #3: model-independent guardrail — external flow with corroboration
            if e.src_internal is False and self._host_has_flag(host):
                return "external_corroborated" if self._dedup("external", host, dst, ts) else None
        if e.event_type == "process":
            cmd = norm_cmd(e.dest_entity or "")
            if cmd and cmd in self.process_baseline:
                return None  # learned-normal command (system services, cron, …)
            if killchain_phase(e) == "discovery":
                return "discovery" if self._dedup("discovery", host, cmd, ts) else None
            if self._host_has_anomaly(host):
                return "process_corroborated" if self._dedup("corroborated", host, cmd, ts) else None
        return None

    def _prune(self) -> None:
        if not self.recent:
            return
        latest = max(e.timestamp for e in self.recent)
        cutoff = latest - timedelta(seconds=2 * self.window_seconds)
        self.recent = deque(e for e in self.recent if e.timestamp >= cutoff)
        self._seen_flags = {k: t for k, t in self._seen_flags.items() if t >= cutoff}

    def _correlate(self) -> list[tuple[str, Incident]]:
        new_hc: list[tuple[str, Incident]] = []
        for inc in correlate(list(self.recent), key_fn=target_of, window_seconds=self.window_seconds):
            iid = incident_id(inc)
            self.incidents[iid] = inc
            if inc.high_confidence and iid not in self._high_conf:
                self._high_conf.add(iid)
                self.bus.publish({"type": "incident", **to_summary(inc).model_dump()})
                self._log("correlator", f"{iid} → HIGH-CONFIDENCE · {inc.entity} · "
                                        f"{len(inc.events)} events / {len(inc.sources)} sensors / "
                                        f"{len(inc.phases)} phases")
                new_hc.append((iid, inc))
        return new_hc

    async def _attribute(self, iid: str, inc: Incident) -> None:
        try:
            view = self.attribute_fn(inc)
            self.attributions[iid] = view
            self.stats["attributed"] += 1
            self._log("attribution", f"{iid} mapped to {len(view.techniques)} ATT&CK techniques"
                                     + (" (grounded)" if view.grounded else ""))
            self.bus.publish({"type": "attribution", "id": iid, **view.model_dump()})
        except Exception:
            # attribution failure must never break the pipeline
            self.stats["attribution_failed"] += 1
            self._log("attribution", f"{iid} attribution failed (LLM unreachable) — detection unaffected")

    # ---- operator / query ----
    def reset_baseline(self) -> None:
        delete_baseline(self.state_dir)
        self.auth_sentinel = self.net_sentinel = None
        self.auth_threshold = self.net_threshold = None
        self.process_baseline = set()
        self._seen_flags = {}
        self.warmup_events = []
        self._t0 = None
        self.recent.clear()
        self.mode = "warmup"
        self._log("baseline", "operator reset — re-learning normal from scratch")

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
            "warmup_seconds": self.warmup_seconds,
            "incident_count": len(self.incidents),
            "high_confidence_count": len(self._high_conf),
            "flagged_recent": len(self.recent),
            "baseline_ready": self.auth_sentinel is not None or self.net_sentinel is not None,
            "fleet": self.fleet.snapshot(),
            "pipeline": {
                "stats": dict(self.stats),
                "activity": list(self.activity)[-15:],
                "window_seconds": self.window_seconds,
                "process_baseline_size": len(self.process_baseline),
                "detectors": {"auth": self.auth_sentinel is not None,
                              "network": self.net_sentinel is not None},
            },
        }
