"""Feed a benign warmup batch then a C553-style attack to a running Prahari, so the
live dashboard flips warmup→monitoring and lights up — no VM needed.

    cd apps/api && PYTHONPATH=. python scripts/demo_feed.py
Env: PRAHARI_URL (default http://localhost:8000), PRAHARI_INGEST_TOKEN (default dev-token).
"""
from __future__ import annotations

import json
import os
import time
import urllib.request

URL = os.environ.get("PRAHARI_URL", "http://localhost:8000").rstrip("/")
TOKEN = os.environ.get("PRAHARI_INGEST_TOKEN", "dev-token")


def _ev(h, m, s, et, source, **kw):
    d = {"timestamp": f"2017-07-05T{h:02d}:{m:02d}:{s:02d}+00:00", "event_type": et, "source": source, "raw": "x"}
    d.update(kw)
    return d


def _post(batch):
    req = urllib.request.Request(f"{URL}/api/ingest", data=json.dumps(batch).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


benign = [_ev(15, 0, i, "auth", "linux-auth", source_entity="U100", src_host="WU100",
              dst_host="C2", auth_type="Kerberos", outcome="success", asset_criticality="medium") for i in range(12)]
benign += [_ev(15, 0, i, "network_flow", "conntrack", src_host="WU100", dst_ip="10.0.0.9",
               bytes=200 + i, duration=1.0, src_internal=True) for i in range(6)]

attack = [
    _ev(3, 32, 16, "auth", "linux-auth", source_entity="U100", src_host="WU100", dst_host="C553",
        auth_type="NTLM", outcome="success", asset_criticality="critical"),
    _ev(3, 32, 19, "process", "sysmon", source_entity="U100", src_host="C553",
        dest_entity="cmd /c whoami", asset_criticality="critical"),
    _ev(3, 32, 24, "network_flow", "cicids", src_host="C553", dst_ip="52.84.23.17",
        bytes=54000, duration=900.0, src_internal=False, asset_criticality="critical"),
]

print("warmup batch:", _post(benign))
time.sleep(1)
print("attack batch:", _post(attack))
print("→ open http://localhost:3000 — banner flips to Monitoring and C553 appears live.")
