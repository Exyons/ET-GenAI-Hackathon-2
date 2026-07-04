"""Sentinel operating-point sweep on the cached LANL slice. Fast (no gzip re-scan).

Sweeps the anomaly-score quantile threshold, and adds a compound gate that also
requires >=2 behavioural novelty signals (new dest / new src / off-hours / rare auth)
- the single-detector version of "compound" scoring - to trade FPs for precision.

Usage: cd apps/api && PYTHONPATH=. uv run python scripts/run_threshold_sweep.py [T0] [T1] [CAP]
"""
from __future__ import annotations

import gzip
import sys
from pathlib import Path

import numpy as np

from prahari.detect.metrics import evaluate
from prahari.detect.sentinel import Sentinel
from prahari.enrich import enrich
from prahari.parsers.lanl import parse_lanl_line

ROOT = Path(__file__).resolve().parents[3]
NOVELTY_IDX = (0, 1, 2, 3)  # is_new_dest, is_new_src, auth_type_rarity, hour_novelty


def _redteam():
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
        sys.exit(f"cache {cache.name} missing — run run_real_benchmark.py first")

    redteam = _redteam()
    events = [enrich(parse_lanl_line(ln, redteam)) for ln in cache.read_text().splitlines() if ln.strip()]
    events.sort(key=lambda e: e.timestamp)
    split = len(events) // 2
    train, test = events[:split], events[split:]

    sentinel = Sentinel(random_state=0).fit(train)
    train_scores = sentinel.anomaly_scores(train)
    test_scores = sentinel.anomaly_scores(test)

    # per-test-event count of strong novelty signals (>=0.5) among novelty features
    feats = np.array([sentinel.baseline.featurize(e) for e in test], dtype=float)
    signal_count = (feats[:, NOVELTY_IDX] >= 0.5).sum(axis=1)

    print(f"cache {cache.name}: train={len(train)} test={len(test)} "
          f"redteam_in_test={sum('redteam' in e.labels for e in test)}\n")
    print(f"{'operating point':28s} {'recall':>7} {'prec':>7} {'f1':>7} {'fpr':>8}  tp/fp/fn")

    def report(name, flags):
        m = evaluate(test, list(flags))
        print(f"{name:28s} {m.recall:7.3f} {m.precision:7.4f} {m.f1:7.4f} {m.fpr:8.4f}  "
              f"{m.tp}/{m.fp}/{m.fn}")

    for q in (0.95, 0.99, 0.995, 0.999):
        thr = float(np.quantile(train_scores, q))
        report(f"quantile {q}", test_scores >= thr)

    # compound gate at a moderate threshold: score high AND >=2 novelty signals
    thr99 = float(np.quantile(train_scores, 0.99))
    report("q0.99 + >=2 signals", (test_scores >= thr99) & (signal_count >= 2))
    thr95 = float(np.quantile(train_scores, 0.95))
    report("q0.95 + >=2 signals", (test_scores >= thr95) & (signal_count >= 2))
    report("q0.95 + >=3 signals", (test_scores >= thr95) & (signal_count >= 3))


if __name__ == "__main__":
    main()
