# ATT&CK Attribution Demo — the C553 incident

Grounded RAG attribution of the fused C553 incident, running **fully local / air-gapped**.

**Models:** `embeddinggemma` (local embeddings, 768-dim) + `qwen2.5:7b` (local reasoning).
No cloud API, no network egress — classified telemetry never leaves the box.
**Corpus:** 697 MITRE ATT&CK enterprise techniques (`corpus/attack_techniques.json`).
**Command:** `cd apps/api && PYTHONPATH=. uv run python scripts/run_attribution_demo.py`

## Incident (fused, 3 sources)

```
Incident on entity C553. Phases: command_and_control, discovery, lateral_movement.
- auth   lateral_movement:      U342@DOM1 remote login (NTLM) to C553
- process discovery:            U342@DOM1 executed cmd /c whoami
- network command_and_control:  outbound connection to 52.84.23.17
```

## Attribution output (run 2026-07-03)

| Timeline step | Technique | Correct? |
|---|---|---|
| NTLM remote login (lateral movement) | **T1021.006** Remote Services | ✓ (Remote Services family) |
| `cmd /c whoami` (discovery) | **T1057** Process Discovery | ✓ exact |
| outbound beacon (C2) | **T1071.002** Application Layer Protocol | ✓ (App-Layer C2 family) |

**Predicted next tactic:** `command-and-control → exfiltration (1.0)`.

**Grounding / hallucination guard:** all three cited IDs were in the retrieved candidate
set (22 techniques incl. T1021/T1021.004/T1057/T1059.003/T1071.*/T1550). No un-retrieved
ID could be emitted.

## How it got here (honest notes)

- **Retrieval quality** depended on **per-event queries**: a single incident-level query was
  swamped by the discovery text and missed lateral/C2. Querying per timeline step surfaces
  each phase's techniques.
- **Reasoning quality** scaled with model size: `qwen2.5:3b` under-mapped (picked only
  discovery techniques); `qwen2.5:7b` mapped all three kill-chain steps correctly.
- **Cloud models** (`qwen3.5:cloud`, 397B) returned `403 Forbidden` without an Ollama account
  sign-in. Using local models instead is both a fallback and the stronger story — the whole
  attribution runs air-gapped.
- Event phrasing is derived from real fields (`auth_type`, external/outbound flags), not
  hand-fed technique hints — the prompt never names the expected techniques.
