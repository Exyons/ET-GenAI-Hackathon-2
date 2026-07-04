# Prahari — How It Works (end-to-end technical guide)

A step-by-step walkthrough of the whole system: what each file does, how the Isolation
Forest detects anomalies, how the LLM is wired, and exactly what gets fed to it. Written
against the real code in `apps/api/prahari/` and `apps/web/`.

---

## 0. The 30-second mental model

```
raw logs → CanonicalEvent → enrich → Sentinel (ML anomaly) → Correlator (fuse → Incident)
         → Attributor (ATT&CK RAG via local LLM) + Predictor → FastAPI → Next.js console
```

One rule governs the whole design: **real ML does the detection; the LLM only reasons and
explains.** Everything before the Attributor is deterministic Python + scikit-learn. The LLM
never decides *whether* something is an attack — it only *names* an attack the ML already found.

---

## 1. Ingestion — everything becomes one shape

### 1.1 The common schema — `prahari/schema.py`
`CanonicalEvent` is a Pydantic model. Every log line from every source is parsed into this one
shape so the rest of the system speaks one language:

```
timestamp, event_type(auth|network_flow|process), source_entity, dest_entity,
src_ip/dst_ip, src_host/dst_host, action, outcome, auth_type, bytes, duration,
src_internal, asset_criticality, source, labels[], raw
```

- `labels` carries ground truth (`"redteam"`, `"attack"`) — used only for scoring, never for detection.
- `raw` is the **untouched original line** — the audit trail. Every alert can point back to the exact record.

### 1.2 Parsers — `prahari/parsers/`
Each parser fills what it can, leaves the rest `None`.

| File | Function | Source format |
|---|---|---|
| `lanl.py` | `parse_lanl_line(line, redteam)` | `time,src_user,dst_user,src_comp,dst_comp,auth_type,...` (9 cols). Joins each line's `(time,user,src,dst)` against the **red-team set** to attach the `redteam` label. |
| `lanl.py` | `parse_lanl_proc_line` / `parse_lanl_flow_line` | LANL `proc.txt` (process starts) and `flows.txt` (network). |
| `cicids.py` | `parse_cicids_row` / `parse_cicids_ml_row` | CICIDS2017 flow CSVs (two variants; the ML variant has features + label but no IP/timestamp). |
| `process.py` | `parse_sysmon_obj` / `parse_otrf_obj` | Sysmon JSON. `parse_otrf_obj` keeps only `EventID==1` (process create) and maps real OTRF fields (`Hostname`, `@timestamp`, `User`). |

`load_redteam(path)` builds the red-team key set: `(time, user, src_comp, dst_comp)`.

### 1.3 Enrichment — `prahari/enrich.py`
`enrich(event)` adds context the raw log doesn't have:
- `asset_criticality` from `ASSET_CRITICALITY` lookup (demo CMDB: `C553 → "critical"`).
- `src_internal` from `is_internal(ip)` (RFC1918 prefixes → internal).

### 1.4 Stream + replay — `stream.py`, `replay.py`
- `merge_ordered(*streams)` — flattens all sources, stable-sorts by `timestamp`.
- `replay(events, speed=100, sleep)` — a generator that yields events in order, sleeping
  `gap_seconds / speed` between them so a day of logs plays in minutes. `sleep` is injected so
  tests run instantly.

---

## 2. Sentinel — behavioural anomaly detection (the ML core)

Two detectors: **auth** (`Sentinel`) and **network** (`NetworkSentinel`). This is where the
"detect by behaviour, not signatures" claim lives.

### 2.1 Per-entity feature engineering — `prahari/detect/features_auth.py`
`AuthBaseline` learns what's normal **for each user** from history:
- `user_dests[u]` — set of hosts u normally logs into
- `user_srcs[u]` — set of hosts u logs in *from*
- `user_authtype[u]` — Counter of auth mechanisms (Kerberos vs NTLM)
- `user_hours[u]` — set of hours u is normally active

`featurize(event)` turns one event into **5 numbers in [0,1]**, each a behavioural novelty signal:

| Feature | Meaning | 1.0 means |
|---|---|---|
| `is_new_dest` | host never seen for this user | lateral move to a new machine |
| `is_new_src` | source host never seen | logging in from somewhere new |
| `auth_type_rarity` | `1 − freq(this auth type)` | rare mechanism (NTLM where Kerberos is normal ≈ pass-the-hash) |
| `hour_novelty` | active hour never seen | 3 a.m. login |
| `dest_criticality` | asset importance (0.25–1.0) | targeting a critical host |

This is UEBA: the baseline is **learned from data**, not hand-written rules. And it's
**interpretable** — the alert literally reads "new dest + NTLM + off-hours + critical asset."

### 2.2 How the Isolation Forest works — `prahari/detect/sentinel.py`

**The algorithm (conceptually).** An Isolation Forest builds many random binary trees. To build
one tree, it repeatedly picks a *random feature* and a *random split value* between that
feature's min and max in the sample, partitioning points until each is isolated. The key insight:
**anomalies are few and different, so they get isolated in fewer splits** — their average
path length from root to leaf is short. Normal points sit in dense regions and take many splits
to isolate. The anomaly score is a function of that average path length across all trees.

**In our code.** `Sentinel.fit(train_events)`:
1. `AuthBaseline.fit(auth)` — learn the per-user baselines.
2. Featurize every training auth event → an `(n, 5)` matrix `X`.
3. `IsolationForest(random_state=0, contamination="auto").fit(X)` — `random_state=0` makes it
   reproducible.
4. Store the min/max of the training anomaly scores (for normalization later).

`sklearn`'s `score_samples(X)` returns the *opposite* of the anomaly score (lower = more
abnormal), so we **negate** it — higher = more anomalous — everywhere.

**Why it isn't Isolation-Forest-only (the honest engineering).** Two real problems surfaced
while building this:
- IF can only split on features that **vary in the training data**. But `is_new_dest` and
  `hour_novelty` are 0 for essentially all benign training events — exactly the columns that
  carry the strongest attack signal. IF effectively ignores them.
- IF **saturates** for extreme outliers: a point 3σ out and a point 2000σ out both isolate at
  depth ~1, so IF can't tell "clearly outside" from "extremely outside."

So `Sentinel` is an **ensemble**, which is what the spec calls for ("Isolation Forest + a
probabilistic novelty score"):

```
anomaly_score = 0.7 · novelty_score + 0.3 · if_norm
```

- `novelty_score = WEIGHTS · features`, with `WEIGHTS = [0.28, 0.14, 0.18, 0.16, 0.24]`
  (new-dest and criticality weighted highest). This is the primary, interpretable signal.
- `if_norm` = the min-max-normalized Isolation Forest score. Secondary — it adds sensitivity to
  subtler multivariate patterns.

The novelty score dominates (0.7) so a genuine multi-signal low-and-slow attack reliably
outranks a benign single-feature outlier, while IF still contributes real ML.

**Scoring & flagging.**
- `anomaly_score(event)` — one event.
- `anomaly_scores(events)` — vectorised (one `score_samples` call) for millions of rows.
- `suggest_threshold(train, quantile)` — the qth-percentile of *training* scores.
- `flag_anomalies(events, threshold)` — `score ≥ threshold`.

### 2.3 Network detector — `prahari/detect/network.py`
`NetworkSentinel` is a **StandardScaler + IsolationForest** on `[bytes, duration]`. Scaling is
required: without it, IF's random splits are biased by the wildly different raw ranges (bytes ~200
vs duration ~1100 vs an attack at 54000/900000). Here IF works well because the features are
continuous with real variance — its home turf.

### 2.4 The baseline built to lose — `prahari/detect/signature.py`
`SignatureBaseline` models classic IOC matching: it flags only known-bad IPs or known-bad command
substrings. It has **no concept of behavioural novelty**, so a valid-credential login to an
internal host (the red-team's whole method) passes straight through. On real LANL data it scores
**0.00 recall** — which is the point: it's the honest contrast that proves behavioural detection's
value.

### 2.5 Metrics — `prahari/detect/metrics.py`
`Metrics(tp,fp,fn,tn)` with `precision/recall/f1/fpr` properties; `evaluate(events, predicted,
positive_label)` compares flags against the `labels` ground truth. This is how we get "0.79 vs
0.00" — measured, never asserted.

---

## 3. Correlator — fusing anomalies into incidents

Single-source per-event detection is high-recall but noisy. Precision comes from **fusion**.

### 3.1 Kill-chain tagging — `prahari/correlate/killchain.py`
- `killchain_phase(event)`: auth → `lateral_movement`; process with a discovery command
  (whoami/ipconfig/net/…) → `discovery`, else `execution`; network → `command_and_control`.
- `actor_of(event)` = the acting identity; `target_of(event)` = the host acted upon
  (auth→`dst_host`, process/network→`src_host`). Two lenses on the same data.

### 3.2 The Incident — `prahari/correlate/incident.py`
An `Incident` is a time-clustered set of events for one entity, with computed properties:
- `phases`, `sources` — the distinct kill-chain phases and telemetry sources present.
- `compound_score` = `0.35·source_diversity + 0.30·phase_diversity + 0.15·volume + 0.20·max_criticality`
  (each term normalized to [0,1]). C553 = 0.94.
- `high_confidence` = **≥2 sources AND ≥2 phases** — the "no single sensor would flag it" bar.
- `is_true_positive` = any event carries a `redteam`/`attack` label.

### 3.3 Correlation + triage — `correlator.py`, `triage.py`
- `correlate(events, key_fn, window_seconds)` — group by `key_fn` (actor or target), split each
  group into incidents wherever the time gap exceeds the window, return sorted by compound score.
- `triage(flagged_events, min_events)` — actor-correlate the flags and keep only bursts
  (a real intrusion is a burst; scattered false positives are singletons).

**The honest finding** (`docs/benchmarks/lanl-correlation-results.md`): on *auth-only* data,
correlation halves FPs but can't reach precision — every incident is single-source. The real fix
is multi-source `high_confidence`, proven in Phase 3.5.

---

## 4. Attributor — how the LLM is wired

This is the only place an LLM runs. It maps an already-detected `Incident` to MITRE ATT&CK
techniques, **grounded** so it can't invent technique IDs. Everything runs **locally / air-gapped**.

### 4.1 The corpus — `prahari/attribute/corpus.py`
- `scripts/build_attack_corpus.py` downloads MITRE's enterprise-attack STIX and trims it to
  `corpus/attack_techniques.json` — **697 techniques**, each `{id, name, tactics, description}`.
- `TechniqueDoc.text()` renders one technique as retrieval text:
  `"T1021 Remote Services. Tactics: lateral-movement. Adversaries may use valid accounts..."`

### 4.2 Retrieval — `prahari/attribute/retriever.py`
`Retriever(embed_fn)`:
- `fit(corpus)` — calls `embed_fn` on all 697 technique texts → an `(697, dim)` matrix,
  **L2-normalized**.
- `retrieve(query, k)` — embeds the query, computes cosine similarity (`matrix @ query`), returns
  the top-k `(TechniqueDoc, score)`.

No vector DB — 697 rows fit in a numpy array in memory. Simpler and more sovereign.

### 4.3 The Attributor — `prahari/attribute/attributor.py`
`Attributor.attribute(incident)` does four things:

**(a) Summarize the incident → text.** `summarize_incident(incident)` produces:
```
Incident on entity C553. Phases: command_and_control, discovery, lateral_movement. Timeline:
- auth lateral_movement: U342@DOM1 remote login (NTLM) to C553
- process discovery: U342@DOM1 executed cmd /c whoami
- network_flow command_and_control:  outbound connection to 52.84.23.17
```
The per-event phrasing (`_event_detail`) is derived from **real fields** — `auth_type`, the
external/outbound flag — not hand-fed technique hints.

**(b) Retrieve per event, not once.** A single incident-level query gets swamped by the busiest
phase (early on, retrieval returned only *discovery* techniques and missed lateral/C2). So the
Attributor issues **one query per timeline step** plus the summary, retrieves top-k for each, and
**unions** the results (keeping the best score per technique id). This guarantees every phase's
techniques surface.

**(c) Ask the LLM to choose + explain.** It builds this prompt (`_PROMPT`):
```
You are a SOC analyst mapping an intrusion to MITRE ATT&CK.
For EACH step in the incident timeline, choose the single candidate technique ID that
best matches that step's action. Make sure lateral movement (a remote login), the
executed command, and any outbound command-and-control traffic are each mapped when present.
Respond ONLY as JSON: {"technique_ids": ["T####", ...], "explanation": "..."}
Use ONLY technique IDs from the candidate list below.

INCIDENT:
<the summary from step (a)>

CANDIDATE TECHNIQUES:
T1021 Remote Services: Adversaries may use valid accounts...
T1057 Process Discovery: ...
T1071.002 Application Layer Protocol: ...
... (the unioned retrieved set)
```
It calls `chat_fn(prompt)` and parses the JSON out of the reply (tolerant of extra prose).

**(d) The hallucination guard.** It keeps **only** technique IDs that were in the retrieved
candidate set: `ids = [t for t in parsed["technique_ids"] if t in retrieved_ids]`. If the model
invents `T9999`, it's dropped. The output `Attribution(technique_ids, explanation, retrieved_ids)`
is therefore always grounded in real, retrieved ATT&CK techniques.

### 4.4 What is fed to which model — `prahari/attribute/ollama.py`
Two local Ollama models, over plain HTTP to `localhost:11434`:

| Model | Endpoint | What it receives | What it returns |
|---|---|---|---|
| `embeddinggemma` (local, 768-dim) | `POST /api/embed` | the 697 technique texts (once, at `fit`) and each per-event query string | embedding vectors |
| `qwen2.5:7b` (local) | `POST /api/chat` (`stream:false`) | the prompt above = incident summary + the unioned candidate techniques (id + name + description) | JSON `{technique_ids, explanation}` |

Nothing else reaches the LLM — not raw logs, not the whole corpus, just the summarized incident
plus a shortlist of candidate techniques. Cloud models (`qwen3.5:cloud`, 397B) return `403`
without an Ollama account sign-in, so we use local models — which is also the stronger story:
**classified telemetry never leaves the box.**

### 4.5 Prediction — `prahari/attribute/predictor.py`
`TacticPredictor` is a **Markov model**: `fit(sequences)` counts tactic→next-tactic transitions;
`predict_next(current, k)` returns the most likely next tactics with probabilities. Seeded with
`ATTACK_TACTIC_PRIOR` (typical kill-chain orderings). For C553's C2 phase it predicts
`exfiltration (1.0)`. Assumptions are explicit and testable — no LLM guessing.

---

## 5. Serving it — API + dashboard

### 5.1 FastAPI — `prahari/api/`
- `demo.py` — builds the C553 incident by running the **real** `correlate(...)` over a fused
  event set, and attaches the **recorded** attribution (`ATTRIBUTIONS`) so requests are fast and
  need no live Ollama.
- `models.py` — Pydantic response shapes (`IncidentSummary`, `IncidentDetail`, `EventView`,
  `AttributionView`, `MetricsView`).
- `serialize.py` — `Incident` → view models.
- `routes.py` — `GET /api/metrics`, `GET /api/incidents` (compound-ranked), `GET /api/incidents/{id}`.
- `main.py` — the FastAPI app + CORS for the Next.js dev server.

### 5.2 Next.js console — `apps/web/`
- `lib/api.ts` — typed fetchers hitting the API.
- `app/page.tsx` — command view: the proof strip (`0.79 vs 0.00`, MTTD, techniques) + incidents
  ranked by compound score.
- `app/incidents/[id]/page.tsx` — the hero: the fused-timeline spine + the ATT&CK card + the
  human-gated respond button.
- `app/globals.css` — the "night-watch" design system (ink + amber phosphor, Roboto).

A request's journey: browser → Next.js server component → `fetch` FastAPI → real correlated
incident + attribution → rendered timeline.

---

## 6. Real multi-source fusion — `prahari/data/multisource.py`
`build_incidents(auth, proc, flow, redteam, window)` parses all three LANL sources, enriches,
and correlates **by target host**. On real data, 9 of 11 red-team hosts fuse auth+process+network
into `high_confidence` incidents — the real-data version of C553
(`docs/benchmarks/lanl-multisource-results.md`).

---

## 7. File-by-file index (what code does what)

| Path | Responsibility |
|---|---|
| `prahari/schema.py` | `CanonicalEvent` common event model |
| `prahari/parsers/lanl.py` | LANL auth + proc + flow parsers, red-team labelling |
| `prahari/parsers/cicids.py` | CICIDS2017 flow parsers (both variants) |
| `prahari/parsers/process.py` | Sysmon + OTRF process parsers |
| `prahari/enrich.py` | asset criticality + internal/external enrichment |
| `prahari/stream.py`, `replay.py` | time-order merge + compressed replay |
| `prahari/detect/features_auth.py` | per-user behavioural feature engineering (UEBA) |
| `prahari/detect/sentinel.py` | ensemble auth detector (IsolationForest + novelty) |
| `prahari/detect/network.py` | scaled IsolationForest flow detector |
| `prahari/detect/signature.py` | IOC baseline (built to lose) |
| `prahari/detect/metrics.py` | precision/recall/F1/FPR |
| `prahari/correlate/killchain.py` | phase tagging + entity keys |
| `prahari/correlate/incident.py` | Incident + compound score + high_confidence |
| `prahari/correlate/correlator.py` | time-clustered correlation |
| `prahari/correlate/triage.py` | actor burst filter |
| `prahari/attribute/corpus.py` | ATT&CK corpus loader (697 techniques) |
| `prahari/attribute/retriever.py` | embed + cosine top-k retrieval |
| `prahari/attribute/attributor.py` | RAG reasoning + hallucination guard |
| `prahari/attribute/predictor.py` | Markov next-tactic |
| `prahari/attribute/ollama.py` | Ollama embed + chat HTTP adapters |
| `prahari/api/*` | FastAPI view models, demo scenario, serializers, routes |
| `prahari/data/lanl_slice.py`, `multisource.py` | streaming slicers + real multi-source builder |
| `apps/web/*` | Next.js SOC console |
| `scripts/run_*.py` | manual runners for the real benchmarks (recorded in `docs/benchmarks/`) |

---

## 8. How to run it

```bash
# tests (the ground truth for every claim)
cd apps/api && uv run pytest -q            # 62 tests

# the live stack
cd apps/api && uv run uvicorn prahari.main:app --port 8000
cd apps/web && npm run start -- --port 3000   # → http://localhost:3000

# the real experiments (multi-GB, manual; results in docs/benchmarks/)
PYTHONPATH=. uv run python scripts/run_real_benchmark.py        # 0.79 vs 0.00
PYTHONPATH=. uv run python scripts/run_attribution_demo.py      # air-gapped ATT&CK
PYTHONPATH=. uv run python scripts/run_multisource_incident.py  # 9/11 hosts fuse
```

Every headline number traces to a script + a recorded result in `docs/benchmarks/`, and every
automated decision traces to `CanonicalEvent.raw` — full auditability, end to end.
