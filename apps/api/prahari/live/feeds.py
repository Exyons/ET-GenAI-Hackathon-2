from __future__ import annotations

import threading
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from prahari import config
from prahari.live import threatintel

# Keeps blocklist data fresh: pulls the configured feed URLs and writes them into
# threatintel/ so the offline enricher picks them up. Runs on a schedule (main.py)
# and can be triggered on demand. A feed that fails is recorded and skipped —
# never fatal — so the box keeps working on bundled + operator data when offline.
_lock = threading.Lock()
_state: dict = {"last_update": None, "feeds": {}}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _http_get(url: str, timeout: float = 20.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "prahari-threatintel/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - operator-configured URL
        return r.read().decode("utf-8", "replace")


def _count(body: str) -> int:
    return sum(1 for ln in body.splitlines() if ln.split("#", 1)[0].strip())


def _feed_name(url: str, i: int) -> str:
    stem = url.rstrip("/").rsplit("/", 1)[-1].split("?")[0] or f"feed{i}"
    safe = "".join(c if c.isalnum() or c in "-." else "-" for c in stem)
    return f"feed-{safe}"


def refresh(fetch=_http_get) -> dict:
    """Pull every configured feed into threatintel/ and reset the enricher cache."""
    d = Path(config.THREATINTEL_DIR)
    d.mkdir(parents=True, exist_ok=True)
    results: dict = {}
    for i, url in enumerate(config.THREATINTEL_FEEDS):
        try:
            body = fetch(url)
            (d / f"{_feed_name(url, i)}.txt").write_text(body)
            results[url] = {"ok": True, "entries": _count(body), "error": None, "at": _now()}
        except Exception as e:  # unreachable / bad content — keep the last file on disk
            results[url] = {"ok": False, "entries": 0, "error": f"{type(e).__name__}: {str(e)[:160]}", "at": _now()}
    threatintel.reset_cache()
    with _lock:
        _state["last_update"] = _now()
        _state["feeds"] = results
    return status()


def status() -> dict:
    with _lock:
        st = {"last_update": _state["last_update"], "feeds": dict(_state["feeds"])}
    return {
        **st,
        "configured_feeds": list(config.THREATINTEL_FEEDS),
        "refresh_hours": config.THREATINTEL_REFRESH_HOURS,
        **threatintel.stats(),
    }
