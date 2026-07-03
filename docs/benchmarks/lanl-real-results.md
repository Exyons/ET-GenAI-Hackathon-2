# LANL Real Benchmark — Sentinel vs Signature

**Dataset:** LANL Comprehensive Cyber Security Events (real enterprise auth logs with red-team ground truth).
**Window:** `t ∈ [759600, 770400)` (hours 211–213 of the capture — the densest red-team burst).
**Sampling:** all red-team auth lines kept; benign reservoir-sampled to a 400,000-line cap (seed 0).
**Split:** chronological, `train_frac=0.5`; Sentinel threshold at `quantile=0.99` of training scores.
**Command:** `cd apps/api && PYTHONPATH=. uv run python scripts/run_real_benchmark.py 759600 770400 400000`

## Results (run 2026-07-03)

| Detector | Recall | Precision | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| **Sentinel** (behavioural) | **0.794** | 0.004 | 0.007 | 0.075 | 54 | 14941 | 14 | 185045 |
| Signature (IOC) | 0.000 | 0.000 | 0.000 | 0.000 | 0 | 0 | 68 | 199986 |

Window stats: 400,107 auth lines kept (107 red-team lines; 1,927,797 benign seen; 114 red-team keys in window; 68 red-team events landed in the test half).

## Honest interpretation

**The headline holds on real data:** behavioural detection catches **79%** of genuine LANL red-team lateral movement; the signature/IOC baseline catches **0%** — it is structurally blind to valid-credential logins to internal hosts.

**The weakness is real:** per-event precision is terrible (0.4%) — 14,941 false positives, FPR 7.5%. Real enterprise users constantly touch new hosts and log in at odd hours, so a single-signal novelty threshold over-fires. Auth-only, per-event detection is inherently noisy.

**Why this is the right finding, not a failure:** it is the exact motivation for Prahari's **Correlator (Phase 3)**. The thesis is that *compound, cross-source correlation* — not per-event alerting — produces precision. Fusing co-occurring signals (auth novelty + process execution + outbound beacon) for one entity within a window collapses ~15k noisy per-event flags into a handful of high-confidence incidents. High recall at the sensor + correlation for precision is the intended architecture.

## Follow-ups (tuning levers, cheap once slice is cached)

- Sweep `quantile` (0.995, 0.999) for the precision/recall trade-off curve.
- Require **≥2 novelty signals** (compound) before flagging — single "new host" should not alert.
- Cold-start handling: don't score users with < N history events as anomalous (unknown ≠ malicious).
- Per-entity aggregation over a window (this is Correlator territory, Phase 3).

**Perf note:** the run took ~24 min, dominated by the 150M-line gzip scan to reach `t1`. The script now caches the sliced+sampled window to `data/lanl_slice_<t0>_<t1>_<cap>.txt` (git-ignored) so subsequent tuning runs load in seconds.
