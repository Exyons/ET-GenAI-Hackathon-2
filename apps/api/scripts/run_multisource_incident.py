"""Build a real multi-source incident from LANL auth+proc+flows for red-team hosts.
Manual (multi-GB): not in CI.

Usage: cd apps/api && PYTHONPATH=. uv run python scripts/run_multisource_incident.py [T0] [T1]
"""
from __future__ import annotations

import gzip
import sys
from pathlib import Path

from prahari.data.lanl_slice import lines_for_hosts, slice_auth_lines
from prahari.data.multisource import build_incidents

ROOT = Path(__file__).resolve().parents[3]


def load_redteam(t0: int, t1: int):
    keys = set(); hosts = set()
    with gzip.open(ROOT / "data/redteam.txt.gz", "rt") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            t, u, s, d = line.split(",")
            if t0 <= int(t) < t1:
                keys.add((t, u, s, d)); hosts.update({s, d})
    return keys, hosts


def _slice(path, hosts, t0, t1, host_fields):
    with gzip.open(ROOT / path, "rt") as fh:
        return list(lines_for_hosts(fh, hosts, t0, t1, host_fields))


def main() -> None:
    t0 = int(sys.argv[1]) if len(sys.argv) > 1 else 150000
    t1 = int(sys.argv[2]) if len(sys.argv) > 2 else 160000
    redteam, hosts = load_redteam(t0, t1)
    print(f"window [{t0},{t1}): {len(redteam)} red-team events, {len(hosts)} hosts")

    with gzip.open(ROOT / "data/auth.txt.gz", "rt") as fh:
        auth = [ln for ln in slice_auth_lines(fh, t0, t1)
                if (p := ln.split(",")) and len(p) >= 5 and (p[3] in hosts or p[4] in hosts)]
    proc = _slice("data/proc.txt.gz", hosts, t0, t1, (2,))
    flow = _slice("data/flows.txt.gz", hosts, t0, t1, (2, 4))
    print(f"sliced: auth={len(auth)} proc={len(proc)} flow={len(flow)}")

    incidents = build_incidents(auth, proc, flow, redteam, window_seconds=600)
    hc = [i for i in incidents if i.high_confidence]
    tp = [i for i in hc if i.is_true_positive]
    print(f"incidents={len(incidents)} high_confidence={len(hc)} of-which-red-team={len(tp)}")

    for inc in sorted(tp, key=lambda i: i.compound_score, reverse=True)[:3]:
        print(f"\n=== {inc.entity}  compound={inc.compound_score:.2f}  "
              f"sources={sorted(inc.sources)} phases={sorted(inc.phases)} ===")
        for e in inc.timeline()[:12]:
            print(f"  {e.timestamp:%H:%M:%S} {e.event_type:13s} {e.source:10s} "
                  f"{(e.source_entity or ''):16s} -> {e.dest_entity or e.dst_host or e.dst_ip or ''}")


if __name__ == "__main__":
    main()
