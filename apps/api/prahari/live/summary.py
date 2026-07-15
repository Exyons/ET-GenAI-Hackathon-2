from __future__ import annotations

import json
import threading
import time
from collections import Counter
from datetime import datetime, timezone

from prahari.api.demo import incident_id
from prahari.correlate.killchain import killchain_phase

# LLM situation summary with caching. The digest (fast, no LLM) is always fresh;
# the narrative is generated in the background and regenerated only when the
# security picture actually changes (signature), so the report never blocks and
# the model isn't re-run on every event tick.
_PROMPT = """You are the lead analyst in a security operations centre for critical \
national infrastructure. Given this machine-readable snapshot of the currently \
monitored state, write a SHORT situation report of 4-6 sentences: the overall \
posture, what is happening right now, the single biggest risk, and what the operator \
should focus on next. Be specific and concise. No preamble, no bullet points, no \
markdown — just the paragraph.

STATE:
{state}
"""

_PHASES = ("lateral_movement", "discovery", "execution", "command_and_control")
_REASONS = ("auth_anomaly", "net_anomaly", "discovery", "process_corroborated", "external_corroborated")

_lock = threading.Lock()
_cache: dict = {"sig": None, "narrative": "", "generated_at": None, "error": None}
_inflight = False
_last_attempt = 0.0
RETRY_SECONDS = 20.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_digest(pipeline) -> dict:
    status = pipeline.status()
    fleet = status["fleet"]
    stats = status["pipeline"]["stats"]
    incidents = sorted(pipeline.incidents.values(), key=lambda i: i.compound_score, reverse=True)
    phase_counts = Counter(killchain_phase(e) for e in pipeline.recent)
    return {
        "mode": status["mode"],
        "baseline_ready": status["baseline_ready"],
        "events_seen": status["events_seen"],
        "rate_epm": fleet["rate_epm"],
        "hosts": len(fleet["hosts"]),
        "hosts_online": sum(1 for h in fleet["hosts"] if (h["last_seen_s"] or 1e9) < 15),
        "flagged_recent": status["flagged_recent"],
        "incident_count": status["incident_count"],
        "high_confidence_count": status["high_confidence_count"],
        "phase_counts": {p: phase_counts.get(p, 0) for p in _PHASES},
        "flag_reasons": {k: stats.get(k, 0) for k in _REASONS},
        "response": status["response"],
        "top_incidents": [
            {"entity": i.entity, "id": incident_id(i), "score": round(i.compound_score, 2),
             "high_confidence": i.high_confidence, "sources": len(i.sources), "phases": len(i.phases)}
            for i in incidents[:5]
        ],
        "attribution_error": status["pipeline"]["attribution_error"],
    }


def _signature(d: dict) -> str:
    # only the security-meaningful fields — not the ever-changing event/rate counters
    meaningful = {
        "mode": d["mode"], "hc": d["high_confidence_count"], "inc": d["incident_count"],
        "flagged": d["flagged_recent"], "phases": d["phase_counts"], "reasons": d["flag_reasons"],
        "response": d["response"], "top": d["top_incidents"], "hosts": d["hosts"],
    }
    return json.dumps(meaningful, sort_keys=True)


def _generate(digest: dict, sig: str, chat_fn) -> None:
    global _inflight
    try:
        text = chat_fn(_PROMPT.format(state=json.dumps(digest, indent=2)))
        with _lock:
            _cache.update(sig=sig, narrative=text.strip(), generated_at=_now(), error=None)
    except Exception as e:  # LLM unreachable — keep the last good narrative, surface why
        with _lock:
            _cache.update(error=f"{type(e).__name__}: {str(e)[:160]}", generated_at=_now())
    finally:
        _inflight = False


def get_summary(pipeline, chat_fn, force: bool = False) -> dict:
    global _inflight, _last_attempt
    digest = build_digest(pipeline)
    sig = _signature(digest)
    with _lock:
        fresh = _cache["sig"] == sig and _cache["error"] is None
        now = time.monotonic()
        should = (force or not fresh) and not _inflight and (now - _last_attempt >= RETRY_SECONDS or force)
        if should:
            _inflight = True
            _last_attempt = now
            threading.Thread(target=_generate, args=(digest, sig, chat_fn), daemon=True).start()
        return {
            "digest": digest,
            "narrative": _cache["narrative"],
            "generated_at": _cache["generated_at"],
            "stale": not fresh,
            "generating": _inflight,
            "error": _cache["error"],
        }
