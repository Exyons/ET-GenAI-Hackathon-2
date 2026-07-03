# Prahari — AI-Driven Cyber Resilience for Critical National Infrastructure
### Design Spec · ET AI Hackathon 2026 · Problem Statement 7

**Date:** 2026-07-03
**Team:** solo (1 builder)
**Deadline:** 2026-07-22 (~19 days)
**Working name:** Prahari (प्रहरी — "sentinel / watchman")

---

## 1. Thesis (one breath)

> Attacks on government infrastructure are found **weeks or months too late** because traditional
> tools wait for known malware *signatures*. Prahari detects attacks by **how systems behave
> abnormally** — fusing auth, network, and endpoint signals into one incident timeline — so it
> catches novel, low-and-slow APTs that signature tools miss, maps them to MITRE ATT&CK with cited
> reasoning and a gated response in seconds, and runs **fully air-gapped** so classified national-
> infrastructure telemetry never leaves the perimeter.

This sentence covers Innovation + Business Impact (50% of score) on its own. Everything below serves it.

---

## 2. Strategy

**Product shape:** A+B hybrid — one deep, real detection→attribution→response pipeline (depth,
real ML, real metrics) *architected and narrated* as a small **multi-agent system** (Innovation
framing), plus a lightweight simulated digital-twin attack-path view as eye-candy.

**Coverage:** the agent topology maps 1:1 onto all five of the problem statement's "what you may
build" bullets. Build 3 for real, keep 2 lightweight. Full-problem coverage anchored by genuine depth.

| # | Problem statement component | Prahari agent | Depth |
|---|---|---|---|
| 1 | Behavioural Anomaly Detection Engine | **Sentinel** | Real ML |
| 2 | APT Attribution & Prediction Agent | **Attributor + Predictor** | Real (RAG + Markov) |
| 3 | Autonomous Incident Response Orchestrator | **Responder + Orchestrator** | Real logic, simulated exec |
| 4 | Government Vulnerability Prioritisation | CVE-map view | Lightweight |
| 5 | Cyber Resilience Digital Twin | Attack-path graph view | Simulated eye-candy |

**Four differentiators:**
1. **India critical-infrastructure framing** — CERT-In advisories in the RAG corpus; government-target
   incidents (AIIMS/CBSE) from the problem statement.
2. **Low-and-slow APT detection with LANL red-team ground truth** — real precision/recall on lateral
   movement that signature tools miss.
3. **Compound cross-source correlation** — the fused auth+network+endpoint timeline (the challenge's core).
4. **Sovereign / air-gapped deployment** — runs fully on-prem via local Ollama; classified OT telemetry
   legally cannot go to a US cloud API. No cloud-API team can match this on national infrastructure.

**Golden rule:** real ML does the *detection*; the LLM does the *reasoning and explanation*. Enrich
deterministically, then reason. Not an LLM wrapper — protects Technical Excellence (20%).

---

## 3. Architecture & agent topology

**Deterministic spine (plumbing, not agents):**
- **Ingestion pipeline** — parsers (LANL auth, CICIDS netflow, Sysmon-style process) → common schema
  → enrichment (asset criticality, user role, geo, internal/external) → time-align. Deterministic on purpose.

**Agents (the multi-agent framing):**

| Agent | Job | Brain |
|---|---|---|
| **Sentinel** (Detector) | Per-entity behavioural baselines; scores deviations across auth/net/endpoint | Real ML — Isolation Forest / autoencoder + online scoring. No signatures. |
| **Correlator** | Fuses multi-source events for one entity into a single incident timeline | Deterministic + graph |
| **Attributor** | Maps assembled incident → MITRE ATT&CK techniques with citations | RAG over ATT&CK/Sigma/playbooks via Ollama |
| **Predictor** | Predicts likely next ATT&CK step | Markov transition over ATT&CK tactics + LLM narration |
| **Responder** | Proposes containment playbook, blast-radius gated, human approval | Playbook retrieval + LLM; simulated execution |
| **Orchestrator** | Routes anomaly → correlate → attribute → predict → respond; holds incident state + audit log | State machine |

**Data flow:**
```
raw logs → [Ingestion pipeline] → clean time-ordered stream
        → Sentinel scores each event/entity
        → anomaly cluster fires → Orchestrator opens Incident
        → Correlator assembles fused timeline (+ raw evidence)
        → Attributor (RAG) tags ATT&CK techniques + cites
        → Predictor forecasts next move
        → Responder proposes gated containment
        → SOC dashboard renders timeline + attribution + metrics
        → every step appended to immutable audit log
```

Everything downstream of the Orchestrator is one **Incident** object that accretes evidence — that
object is also the audit trail (satisfies the "full auditability of every automated action" criterion).

---

## 4. Common event schema

Every source maps onto this. Each parser fills what it can, leaves the rest null.

```json
{
  "timestamp": "2017-07-05T15:32:16Z",
  "event_type": "auth",
  "source_entity": "U342@DOM1",
  "dest_entity": "C553",
  "src_ip": null,
  "dst_ip": null,
  "src_host": "C1115",
  "dst_host": "C553",
  "action": "login",
  "outcome": "success",
  "bytes": null,
  "duration": null,
  "src_internal": true,
  "asset_criticality": "high",
  "source": "lanl",
  "labels": ["redteam"],
  "raw": "151036,U342@DOM1,..."
}
```

`raw` is the untouched original = evidence trail / audit anchor. When Prahari flags something it can
show the exact records that triggered it.

**The money moment** — after normalisation, the timeline for host `C553` reads:
```
15:32:16  auth      U342@DOM1   C1115 → C553       login NTLM success   [redteam]
15:32:19  process   U342@DOM1   on C553            execute cmd "whoami"
15:32:24  network   C553 → 52.84.23.17:443         outbound, new dest
```
Each event alone is unremarkable; every signature tool waves all three through. Fused on one timeline
for one entity, they trace lateral movement → reconnaissance → outbound beacon. That correlation, with
the red-team label confirming a real attack, is the screenshot that wins the room. The demo is built
around this.

---

## 5. Detection internals (Sentinel)

**Track 1 — Network anomaly (CICIDS2017 / UNSW-NB15).** Pre-extracted flow features. Isolation Forest
(+ autoencoder ensemble) trained on benign flows → per-flow anomaly score.

**Track 2 — Auth low-and-slow (LANL) ⭐.** Per-entity behavioural baselines. Learn per user/host:
- set of hosts the user normally authenticates to
- normal auth-type mix (Kerberos vs NTLM — NTLM-where-Kerberos-is-normal ≈ pass-the-hash)
- active hours, normal request rate

Engineered per-event features: `is_new_dest_for_user`, `is_new_src_for_user`, `auth_type_rarity`,
`hour_zscore`, `dest_indegree_delta`, `rate_burst`, `cross_criticality_zone`. Isolation Forest over these
+ probabilistic novelty score = ensemble. Interpretable by design → alert reads *"U342 never logged into
C553 before, NTLM, off-hours."*

**Signature baseline (built to lose).** Naive rules engine — known-bad IPs, malware hashes, static
thresholds. Stays silent on the LANL red-team lateral movement. Behavioural flags it. Signature 0 recall
vs Sentinel high recall = the Technical Excellence proof.

---

## 6. Correlator (compound cross-source fusion)

Group anomalous events by entity in a sliding window → order → tag each a coarse kill-chain phase
(initial-access / execution / lateral / discovery / C2 / exfil) by heuristic on event_type + action.
**Compound score fires when an incident spans ≥2 sources AND ≥2 phases in-window** — the "no single
sensor would flag it" moment. Backed by an in-memory graph (networkx now, Neo4j if time) so the attack
path renders → feeds the digital-twin view.

---

## 7. Attribution (Attributor, RAG, air-gapped)

- **Corpus:** MITRE ATT&CK (STIX/JSON) + Sigma rules (ATT&CK-tagged) + analyst playbooks (mukul975/
  Anthropic-Cybersecurity-Skills — community project, credited correctly) + CERT-In advisories (scraped,
  India context).
- **Embeddings:** local Ollama model (`nomic-embed-text` / `mxbai-embed-large`) → **Chroma** (file-based).
  Nothing leaves the box.
- **Reasoning:** Ollama Cloud (larger model) or local model — takes retrieved techniques + incident,
  emits technique IDs + confidence + cited explanation.
- **Hallucination guard:** technique IDs constrained to the retrieved set; each cited `T####` verified
  against the corpus before display. No invented ATT&CK IDs.

---

## 8. Prediction (Predictor)

ATT&CK tactic transition matrix (Markov) primed from OTRF attack sequences / curated prior. Current
tactics → ranked next tactics + techniques. LLM narrates. Assumptions kept **explicit and testable**
(the evaluation focus rewards exactly this).

---

## 9. Response (Responder + Orchestrator)

Retrieve a containment playbook for the attributed techniques (isolate endpoint, revoke credential,
block IP, snapshot VM). Compute blast radius. **Human-approval gate** in the UI shows blast radius before
any action. Execution is **simulated** ("would isolate host C553") — never auto-executed in the demo.
Every proposed/approved action appended to the immutable audit log with the triggering evidence.

---

## 10. Metrics (real numbers on screen, clean provenance)

| Claim | Measured on | Against |
|---|---|---|
| Detection precision / recall / F1 / FPR | LANL red-team + CICIDS labels | signature baseline (~0 recall low-and-slow) |
| APT attribution accuracy @ MITRE technique | OTRF (ships ATT&CK ground-truth labels) | — |
| % response playbook auto-executable | Responder playbooks | count |
| MTTD / MTTR weeks → seconds | replay clock | industry baseline |

Provenance rule: accuracy from labelled data (LANL/CICIDS/OTRF), never from RAG knowledge repos.

---

## 11. Datasets

| Dataset | Role | Note |
|---|---|---|
| CICIDS2017 or UNSW-NB15 | Network anomaly core | Labelled normal+attack, pre-extracted features. UNSW cleaner; CICIDS more realistic. |
| LANL Authentication | APT low-and-slow ⭐ | Real red-team events in normal logins; ground-truth labels. |
| OTRF/Security-Datasets | ATT&CK-mapped telemetry | Safe pre-recorded attack events; **attribution ground truth**. |
| MITRE ATT&CK STIX/JSON | RAG knowledge base | Technique corpus. |
| CERT-In advisories (scrape) | India RAG context | Localisation differentiator. |

Avoid NSL-KDD as headline (1999 traffic). Fine as hour-1 smoke test only.

---

## 12. Frontend (Next.js SOC command dashboard)

Dark ops-room aesthetic. Five screens:
1. **Command view** — live event ticker, global threat level, active-incidents list, MTTD/MTTR counters, topology mini-map.
2. **Incident detail ⭐** — fused per-entity timeline (auth→process→network on one axis), ATT&CK attribution card with citations, predicted next step, compound-score explainer, raw-evidence expander, Respond button.
3. **Attack path / digital twin** — entity graph, attacker path highlighted, scripted "what-if" simulate.
4. **Proof panel** — precision/recall/FPR vs baseline bars, ATT&CK-Navigator-style technique heatmap, MTTD/MTTR.
5. **Audit log** — immutable action trail.

Stack: Next.js App Router + Tailwind, Recharts/visx charts, React-Flow (or Cytoscape) attack graph, **SSE**
for the replay stream. Human-gate = confirm modal showing blast radius before any simulated action.

---

## 13. Backend + replay

FastAPI. **Replay engine** compresses time ~100× (a day of logs in minutes) via Python generators +
timer — no Kafka. SSE pushes events to the dashboard. One Incident object accretes evidence and is the
audit record.

---

## 14. Repo shape (monorepo)

```
prahari/
  apps/api/     FastAPI · ingestion · agents · replay
  apps/web/     Next.js SOC dashboard
  packages/     shared schema types
  data/         download scripts (no raw data committed)
  corpus/       ATT&CK · Sigma · CERT-In build scripts
  docker-compose.yml   api · web · chroma · ollama
```

---

## 15. Sovereign / air-gapped mode

`docker-compose` runs the whole system local. `SOVEREIGN_MODE=true` → zero egress, local Ollama only.
Demo move: cut network, system keeps working. No classified OT telemetry leaves the perimeter. The
differentiator no cloud-API team can match on national infrastructure.

---

## 16. Testing

- **Unit** — parser→schema conformance; enrichment lookups.
- **Detection test doubles as metric** — pytest asserts Sentinel recall on LANL red-team > threshold and
  > signature baseline. Fails build if the core claim regresses.
- **RAG grounding test** — every emitted `T####` exists in corpus (no hallucinated ATT&CK IDs).
- **E2E** — replay seeded scenario → assert incident opens, attribution non-empty, audit log complete.

---

## 17. Tech stack summary

| Layer | Pick |
|---|---|
| Ingestion / "streaming" | Python generators + timer replay (~100× compression) |
| Anomaly detection | PyOD (Isolation Forest / autoencoder) / scikit-learn; River for online |
| Attribution RAG | Ollama (cloud + local) + Chroma + local embeddings |
| Attack-path graph | networkx (Neo4j if time) |
| Backend | FastAPI + SSE |
| Frontend | Next.js App Router + React + Tailwind + Recharts/visx + React-Flow |
| Response | Python functions + UI human-approval gate (simulated exec) |
| Deploy | docker-compose (api · web · chroma · ollama), sovereign mode |

---

## 18. Judging criteria → moves

| Criterion | Weight | Move |
|---|---|---|
| Innovation | 25% | Behavioural (not signature) detection + cross-source fusion + multi-agent + India framing + air-gapped |
| Business Impact | 25% | MTTD/MTTR weeks → seconds, quantified on screen |
| Technical Excellence | 20% | Real ML detection, measured precision/recall vs signature baseline |
| Scalability | 15% | Stateless services + streaming design in the architecture diagram |
| User Experience | 15% | SOC command-center dashboard; the timeline view; one-click human gate |

---

## 19. Build roadmap (2026-07-03 → 2026-07-22)

| Phase | Dates | Exit test |
|---|---|---|
| 0 Scaffold | Jul 3–4 | monorepo + compose up; Ollama answers; dataset scripts pull |
| 1 Ingestion | Jul 4–7 | unified time-ordered stream, red-team labels intact |
| 2 Sentinel + baseline | Jul 7–10 | catches LANL red-team; precision/recall/FPR numbers |
| 3 Correlator + Attributor + Predictor | Jul 10–13 | incident → cited ATT&CK techniques + next step |
| 4 SOC dashboard | Jul 13–17 | C553 story renders live over SSE |
| 5 Responder + audit + CERT-In + sovereign polish | Jul 17–20 | one-command end-to-end demo; network-cut test passes |
| 6 Deck + video + dry runs | Jul 20–22 | 7-slide deck, demo video, architecture diagram, buffer |

Two days of genuine buffer built in.

---

## 20. Demo script (3 minutes)

1. **Hook (20s):** "AIIMS was down two weeks. CBSE breached ahead of board exams. Attacks found months late because tools wait for signatures. Here's the fix."
2. **Normal state (20s):** dashboard streaming benign traffic; baselines green.
3. **The attack (40s):** replay starts; C553 timeline lights up — auth → whoami → beacon. Signature baseline: silent. Prahari: flagged.
4. **The intelligence (40s):** click alert → ATT&CK attribution, predicted next step, cited playbook, gated containment.
5. **The proof (40s):** metrics panel — precision/recall/FPR, MTTD weeks → under a minute, red-team label confirming true positive.
6. **Close (20s):** India framing — CERT-In context, then cut the network live: **still running, air-gapped.** Auditable evidence trail.

---

## 21. Explicitly out of scope

- Real Wazuh/Shuffle/TheHive deployment
- OT/ICS protocol parsing
- Live production streaming (replay only)
- Autonomous containment execution (simulated only)
- Multi-tenant / horizontal scale infra (shown in architecture, not built)

---

## 22. Open items to resolve during build

- CICIDS2017 vs UNSW-NB15 final pick (decide in Phase 1 by file size / cleanliness).
- Ollama Cloud model choice for reasoning (bench 2–3 in Phase 3).
- Neo4j vs networkx for the graph (default networkx; upgrade only if time in Phase 5).
