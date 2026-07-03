"""Real-data proof that correlation fixes the per-event FP problem.

Loads the cached LANL slice, flags test events with Sentinel, then actor-correlates
the flags into incidents and applies the burst filter. Reports how many raw per-event
flags collapse into incidents, and how many true-positive vs false-positive incidents
survive.

Usage: cd apps/api && PYTHONPATH=. uv run python scripts/run_real_correlation.py [T0] [T1] [CAP]
"""
from __future__ import annotations

import sys
from pathlib import Path

from prahari.correlate.correlator import correlate
from prahari.correlate.killchain import actor_of
from prahari.correlate.triage import triage
from prahari.detect.sentinel import Sentinel
from prahari.enrich import enrich
from prahari.parsers.lanl import load_redteam, parse_lanl_line

ROOT = Path(__file__).resolve().parents[3]


def _load_redteam_gz():
    import gzip

    keys = set()
    with gzip.open(ROOT / "data/redteam.txt.gz", "rt") as fh:
        for line in fh:
            line = line.strip()
            if line:
                t, u, s, d = line.split(",")
                keys.add((t, u, s, d))
    return keys


def main() -> None:
    t0 = int(sys.argv[1]) if len(sys.argv) > 1 else 759600
    t1 = int(sys.argv[2]) if len(sys.argv) > 2 else 770400
    cap = int(sys.argv[3]) if len(sys.argv) > 3 else 400_000
    cache = ROOT / f"data/lanl_slice_{t0}_{t1}_{cap}.txt"
    if not cache.exists():
        sys.exit(f"cache {cache.name} missing — run scripts/run_real_benchmark.py first")

    redteam = _load_redteam_gz()
    lines = cache.read_text().splitlines()
    events = [enrich(parse_lanl_line(ln, redteam)) for ln in lines if ln.strip()]
    events.sort(key=lambda e: e.timestamp)

    split = len(events) // 2
    train, test = events[:split], events[split:]

    sentinel = Sentinel(random_state=0).fit(train)
    threshold = sentinel.suggest_threshold(train, quantile=0.99)
    scores = sentinel.anomaly_scores(test)
    flagged = [e for e, s in zip(test, scores) if s >= threshold]

    rt_events_in_test = sum(1 for e in test if "redteam" in e.labels)
    rt_flagged = sum(1 for e in flagged if "redteam" in e.labels)

    def is_machine(actor: str | None) -> bool:
        return bool(actor) and actor.split("@")[0].endswith("$")

    raw_incidents = correlate(flagged, key_fn=actor_of, window_seconds=600)
    incidents = triage(flagged, window_seconds=600, min_events=3)
    tp_inc = [i for i in incidents if i.is_true_positive]
    fp_inc = [i for i in incidents if not i.is_true_positive]

    # Fix (a): exclude machine/computer accounts (standard UEBA — they have
    # inherently high auth fan-out; stolen-credential lateral movement uses
    # interactive user accounts, which is what the red team used).
    flagged_users = [e for e in flagged if not is_machine(e.source_entity)]
    inc_users = triage(flagged_users, window_seconds=600, min_events=3)
    tp_u = [i for i in inc_users if i.is_true_positive]
    fp_u = [i for i in inc_users if not i.is_true_positive]

    print(f"test events:                 {len(test)}")
    print(f"red-team events in test:     {rt_events_in_test}")
    print(f"Sentinel per-event flags:    {len(flagged)}  (red-team caught: {rt_flagged})")
    print(f"actor incidents (raw):       {len(raw_incidents)}")
    print("-- all actors (incl. machine accounts) --")
    print(f"incidents after burst filter:{len(incidents)}  TP={len(tp_inc)} FP={len(fp_inc)}")
    print("-- interactive user accounts only (fix a) --")
    print(f"flagged user-acct events:    {len(flagged_users)}")
    print(f"incidents after burst filter:{len(inc_users)}  TP={len(tp_u)} FP={len(fp_u)}")
    if inc_users:
        print("top user-account incidents by compound score:")
        for i in inc_users[:10]:
            tag = "TRUE-POSITIVE" if i.is_true_positive else "fp"
            print(f"  {i.entity:16s} events={len(i.events):3d} "
                  f"compound={i.compound_score:.3f} phases={len(i.phases)} [{tag}]")


if __name__ == "__main__":
    main()
