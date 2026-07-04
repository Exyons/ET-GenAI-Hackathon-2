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

## Threshold + compound-gate tuning (run 2026-07-03)

`scripts/run_threshold_sweep.py` on the cached slice. Fits Sentinel once; evaluates many
operating points. The compound gate additionally requires ≥N strong behavioural novelty
signals (new dest / new src / off-hours / rare auth) — the single-detector version of
compound scoring.

| Operating point | Recall | Precision | FPR | TP/FP/FN |
|---|---|---|---|---|
| quantile 0.95 | 0.956 | 0.0008 | 0.392 | 65 / 78396 / 3 |
| quantile 0.99 | 0.794 | 0.0036 | 0.075 | 54 / 14941 / 14 |
| quantile 0.995 | 0.794 | 0.0049 | 0.055 | 54 / 11022 / 14 |
| **quantile 0.999** | 0.794 | 0.0057 | **0.047** | 54 / 9433 / 14 |
| q0.99 + ≥2 signals | 0.794 | 0.0040 | 0.068 | 54 / 13594 / 14 |
| q0.95 + ≥2 signals | 0.956 | 0.0010 | 0.321 | 65 / 64181 / 3 |
| q0.95 + ≥3 signals | 0.794 | 0.0022 | 0.120 | 54 / 23978 / 14 |

**Finding (decisive):** tuning the threshold or adding a compound novelty-signal gate does
**not** fix single-source precision. The best FPR (0.047 at q0.999) still means ~9,400 false
positives for 54 true positives; the compound-signal gate barely helps because red-team and
benign high-activity users both trigger multiple novelty signals. Raising the threshold to
0.95 buys +0.16 recall but at FPR 0.39 — unusable.

This is the empirical justification for the architecture: **precision is not a threshold
problem, it is a fusion problem.** Cross-source correlation (Phase 3 + the real multi-source
fusion in `lanl-multisource-results.md`) is where precision comes from — combining *anomalous*
signals across auth + process + network, not tightening one auth detector. Recommended
single-detector operating point: **q0.999** (best FPR at no recall cost), feeding the
Correlator rather than alerting per event.
