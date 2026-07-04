# LANL Multi-Source Fusion — the real C553 moment

Phase 3.5. Fuses real LANL `auth` + `proc` + `flows` for red-team hosts and correlates
by target host to test whether multi-source `high_confidence` incidents form on genuine
red-team activity.

**Setup:** window `t ∈ [150000, 160000)` (early red-team cluster). Slice auth/proc/flows to
the red-team host set; correlate by target host, `window=600s`.
**Command:** `cd apps/api && PYTHONPATH=. uv run python scripts/run_multisource_incident.py 150000 160000`

## Results (run 2026-07-03)

```
window [150000,160000): 10 red-team events, 11 hosts
sliced: auth=1220  proc=3097  flow=3177
incidents=102  high_confidence=21  of-which-red-team=9
```

**9 of 11 red-team hosts** fused into `high_confidence` incidents — each spanning all three
sources (`lanl`, `lanl_proc`, `lanl_flow`) and three kill-chain phases (lateral-movement +
execution + command-and-control), compound score 0.80. Example (C1003): NTLM logins into the
host, `P47` process starts on the host, and outbound flows from the host, fused on one entity.

## Honest interpretation

**What this proves:** on genuine LANL red-team data, correlating by target host fuses auth +
process + network telemetry into real multi-source incidents. The C553 "money moment" — three
sensors, three phases, one entity — is **not synthetic**; it exists in the real data for the
large majority (9/11) of red-team hosts.

**What this does NOT prove (precision-at-scale):** this run pre-sliced to the red-team host
set, so it cannot claim that `high_confidence` separates red-team hosts from benign hosts
across the whole population — most busy enterprise hosts have all three telemetry types
continuously. Getting precision-at-scale requires **per-source anomaly scoring on proc and
flow** (only auth has a behavioural model today), so that fusion combines *anomalous*
signals rather than raw activity. That is the honest next lift.

**Bottom line for the deck:** behavioural detection gives recall on real APT lateral movement;
cross-source fusion is real and demonstrable on the actual LANL red-team hosts; single-source
per-event alerting is noisy by design, and precision comes from fusing anomalies across
sources — the architecture is right, and the remaining work is anomaly models for proc/flow.

## Next

Per-source anomaly scoring for process (per-host normal process baselines) and flow
(already have `NetworkSentinel`), then fuse *flagged* events across sources for
precision-at-scale.
