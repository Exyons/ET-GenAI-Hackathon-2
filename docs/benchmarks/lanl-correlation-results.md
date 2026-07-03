# LANL Correlation — does incident fusion fix the FP problem?

Follow-up to `lanl-real-results.md`. Runs the Phase 3 Correlator over Sentinel's
per-event flags on the real LANL slice.

**Setup:** cached slice `t ∈ [759600, 770400)`, 400k-line cap, `train_frac=0.5`,
Sentinel `quantile=0.99`. Actor-correlation, `window=600s`, burst filter `min_events=3`.
**Command:** `cd apps/api && PYTHONPATH=. uv run python scripts/run_real_correlation.py`

## Results (run 2026-07-03)

| Stage | Count | TP incidents | FP incidents |
|---|---|---|---|
| Sentinel per-event flags | 14,995 (54 of 68 red-team) | — | — |
| Actor incidents (raw) | 7,088 | — | — |
| Burst filter, all actors | 1,358 | 8 | 1,350 |
| Burst filter, **user accounts only** | 833 | 8 | 825 |

## Honest interpretation

**Actor-correlation + burst filter alone does not fix precision on auth-only data.**

1. **Machine accounts dominate the noise.** The largest FP incidents were `C###$@DOM1`
   computer accounts (hundreds of flagged events each) — they legitimately authenticate
   to many hosts, so novelty over-fires. Excluding them (standard UEBA; the red team used
   *user* accounts) roughly halves the FP incidents (1,350 → 825) with no loss of true
   positives (8 → 8).

2. **The remaining FPs are structural.** Every surviving incident scores `compound ≤ 0.35`
   with `phases = 1` — i.e. **single-source**. Benign high-fan-out users (admins, roaming
   accounts) still produce bursts. Auth-only correlation cannot reach the `high_confidence`
   bar (≥2 sources AND ≥2 phases), so it cannot separate these from real intrusions.

## What actually fixes it

The Correlator's `high_confidence` / `compound_score` logic *is* the fix — it just needs
**multiple sources for the same entity**. The design demonstrably works on fused
auth+process+network data (see `tests/test_incident.py`, `tests/test_correlator.py`: the
C553 timeline scores `compound > 0.8`, `high_confidence = True`). On real data the proof
requires wiring LANL `proc.txt` (process events) and `flows.txt` (network) for the same
hosts/window and correlating by target host, then filtering to `high_confidence` incidents.

**Takeaway for the deck (state it honestly):** behavioural detection gives high *recall*
(79% of real APT lateral movement vs signatures' 0%); precision comes from *cross-source
correlation*, not per-event thresholds. Single-source auth alone is a noisy sensor by
design — fusion is the point of the architecture.

## Next step

Phase 3.5 — wire LANL proc + flows, correlate by target host, report `high_confidence`
incident precision/recall on real fused data.
