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
    import responder_windows as responder
    import sources_windows as src
else:
    import responder_linux as responder
    import sources_linux as src

PRAHARI_URL = os.environ.get("PRAHARI_URL", "http://localhost:8000").rstrip("/")
TOKEN = os.environ.get("PRAHARI_INGEST_TOKEN", "dev-token")
SOURCES = [s.strip() for s in os.environ.get("PRAHARI_SOURCES", "auth,process,network").split(",")]
BATCH_MAX = int(os.environ.get("PRAHARI_BATCH_MAX", "50"))
FLUSH_SECONDS = float(os.environ.get("PRAHARI_FLUSH_SECONDS", "2"))
HEARTBEAT_SECONDS = float(os.environ.get("PRAHARI_HEARTBEAT_SECONDS", "10"))
# response layer: poll for approved actions and execute them. Destructive
# (armed) actions ONLY run when this is explicitly enabled — default off.
ACTIONS_ENABLED = os.environ.get("PRAHARI_ACTIONS", "true").lower() == "true"
ALLOW_ARMED = os.environ.get("PRAHARI_ALLOW_ARMED", "false").lower() == "true"
ACTION_POLL_SECONDS = float(os.environ.get("PRAHARI_ACTION_POLL_SECONDS", "3"))

_TAILERS = {"auth": src.tail_auth, "process": src.tail_process, "network": src.tail_network}
ACTIVE = [n for n in SOURCES if n in _TAILERS]

# per-source health, shipped with every heartbeat so the dashboard can show
# exactly what each source is doing (tailing/error + events collected)
STATUS: dict[str, dict] = {n: {"state": "starting", "detail": "", "n": 0} for n in ACTIVE}


def _pump(name, q: queue.Queue) -> None:
    st = STATUS[name]
    while True:
        try:
            st.update(state="tailing", detail="")
            for event in _TAILERS[name]():
                st["n"] += 1
                q.put(event)
            time.sleep(2)  # tailer exited cleanly (e.g. journald rotated); respawn gently
        except FileNotFoundError as e:
            tool = getattr(e, "filename", None) or e
            st.update(state="error", detail=f"'{tool}' not installed")
            print(f"[prahari] source {name} needs '{tool}' which is not installed "
                  f"(see collectors/README.md); retrying in 60s", flush=True)
            time.sleep(60)
        except Exception as e:  # a source dies → log, retry
            st.update(state="error", detail=str(e)[:100])
            print(f"[prahari] source {name} error: {e}; retrying in 5s", flush=True)
            time.sleep(5)


def _post(batch: list[dict]) -> None:
    body = json.dumps(batch).encode()
    req = urllib.request.Request(f"{PRAHARI_URL}/api/ingest", data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {TOKEN}",
                                          "X-Prahari-Host": src.HOSTNAME,
                                          "X-Prahari-Os": src.OS_NAME,
                                          "X-Prahari-Sources": ",".join(src.SOURCE_IDS[n] for n in ACTIVE),
                                          "X-Prahari-Source-Status": json.dumps(STATUS)})
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


def _get_json(path: str):
    req = urllib.request.Request(f"{PRAHARI_URL}{path}",
                                 headers={"Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def _post_json(path: str, body: dict) -> None:
    req = urllib.request.Request(f"{PRAHARI_URL}{path}", data=json.dumps(body).encode(),
                                 method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()


def _responder_loop() -> None:
    from urllib.parse import quote
    while True:
        try:
            actions = _get_json(f"/api/actions/pending?host={quote(src.HOSTNAME)}")
            for a in actions:
                result = responder.run(a, ALLOW_ARMED)
                _post_json(f"/api/actions/{a['id']}/result", result)
                verb = "executed" if result.get("ran") else "dry-run"
                print(f"[prahari] action {a['id']} {a['playbook']}→{a['target']} · {verb}", flush=True)
        except (urllib.error.URLError, TimeoutError):
            pass  # API down; the ingest loop already logs connectivity
        except Exception as e:
            print(f"[prahari] responder error: {e}", flush=True)
        time.sleep(ACTION_POLL_SECONDS)


def main() -> None:
    q: queue.Queue = queue.Queue()
    for name in ACTIVE:
        threading.Thread(target=_pump, args=(name, q), daemon=True).start()
        print(f"[prahari] tailing {name}", flush=True)
    if ACTIONS_ENABLED:
        threading.Thread(target=_responder_loop, daemon=True).start()
        print(f"[prahari] response layer on · armed execution "
              f"{'ENABLED' if ALLOW_ARMED else 'disabled (dry-run only)'}", flush=True)
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
