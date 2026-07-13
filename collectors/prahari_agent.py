#!/usr/bin/env python3
"""Prahari collector — tails auth/process/network telemetry and streams it to
Prahari's /api/ingest. Stdlib only; runs on the monitored machine (Linux or Windows).

    Linux:   PRAHARI_URL=http://prahari:8000 PRAHARI_INGEST_TOKEN=... sudo -E python3 prahari_agent.py
    Windows: set the same env vars, then `python prahari_agent.py` in an admin shell
"""
from __future__ import annotations

import json
import os
import platform
import queue
import threading
import time
import urllib.error
import urllib.request

if platform.system() == "Windows":
    import sources_windows as src
else:
    import sources_linux as src

PRAHARI_URL = os.environ.get("PRAHARI_URL", "http://localhost:8000").rstrip("/")
TOKEN = os.environ.get("PRAHARI_INGEST_TOKEN", "dev-token")
SOURCES = [s.strip() for s in os.environ.get("PRAHARI_SOURCES", "auth,process,network").split(",")]
BATCH_MAX = int(os.environ.get("PRAHARI_BATCH_MAX", "50"))
FLUSH_SECONDS = float(os.environ.get("PRAHARI_FLUSH_SECONDS", "2"))
HEARTBEAT_SECONDS = float(os.environ.get("PRAHARI_HEARTBEAT_SECONDS", "10"))

_TAILERS = {"auth": src.tail_auth, "process": src.tail_process, "network": src.tail_network}
ACTIVE = [n for n in SOURCES if n in _TAILERS]


def _pump(name, q: queue.Queue) -> None:
    while True:
        try:
            for event in _TAILERS[name]():
                q.put(event)
            time.sleep(2)  # tailer exited cleanly (e.g. journald rotated); respawn gently
        except FileNotFoundError as e:
            tool = getattr(e, "filename", None) or e
            print(f"[prahari] source {name} needs '{tool}' which is not installed "
                  f"(see collectors/README.md); retrying in 60s", flush=True)
            time.sleep(60)
        except Exception as e:  # a source dies → log, retry
            print(f"[prahari] source {name} error: {e}; retrying in 5s", flush=True)
            time.sleep(5)


def _post(batch: list[dict]) -> None:
    body = json.dumps(batch).encode()
    req = urllib.request.Request(f"{PRAHARI_URL}/api/ingest", data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {TOKEN}",
                                          "X-Prahari-Host": src.HOSTNAME,
                                          "X-Prahari-Os": src.OS_NAME,
                                          "X-Prahari-Sources": ",".join(src.SOURCE_IDS[n] for n in ACTIVE)})
    delay = 1.0
    while True:
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                r.read()
            return
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"[prahari] ingest failed ({e}); retry in {delay:.0f}s", flush=True)
            time.sleep(delay)
            delay = min(delay * 2, 30)


def main() -> None:
    q: queue.Queue = queue.Queue()
    for name in ACTIVE:
        threading.Thread(target=_pump, args=(name, q), daemon=True).start()
        print(f"[prahari] tailing {name}", flush=True)
    print(f"[prahari] shipping to {PRAHARI_URL}/api/ingest as host {src.HOSTNAME}", flush=True)

    batch: list[dict] = []
    last = time.monotonic()
    last_post = 0.0
    while True:
        try:
            batch.append(q.get(timeout=FLUSH_SECONDS))
        except queue.Empty:
            pass
        now = time.monotonic()
        if batch and (len(batch) >= BATCH_MAX or now - last >= FLUSH_SECONDS):
            _post(batch)
            print(f"[prahari] shipped {len(batch)} events", flush=True)
            batch, last, last_post = [], now, now
        elif not batch and now - last_post >= HEARTBEAT_SECONDS:
            _post([])  # heartbeat: keeps this host visible in the fleet while quiet
            last_post = now


if __name__ == "__main__":
    main()
