# Prahari — 3-Minute Demo Video Script

Shot-by-shot script for the hackathon demo video. Two capture sources:
- **Live dashboard** — http://localhost:3000 (start: `cd apps/api && uv run uvicorn prahari.main:app --port 8000`, then `cd apps/web && npm run start -- --port 3000`).
- **Pitch deck** — the published Artifact (for the hook and the close).

Record in one take at 1080p; the voiceover lines are timed to fit 3:00. Numbers are the **real** recorded results — don't round them up.

---

| Time | On screen | Action | Voiceover |
|---|---|---|---|
| **0:00–0:20** | Deck slide 1–2 (problem) | Hold on the title, then the problem slide. | "AIIMS Delhi was down for two weeks. CBSE was breached ahead of board exams. These attacks were found *weeks late* — because signature tools wait for known malware. But an APT with stolen valid credentials leaves no known indicator. The signature stays silent. Prahari doesn't." |
| **0:20–0:40** | Dashboard **command view** (`/`) | Show the proof strip + the incident list at rest. Hover the top row. | "This is Prahari's SOC console. Real detection numbers up top. Incidents ranked by compound risk — one entity, C553, is flagged high-confidence." |
| **0:40–1:20** | Click into **C553 incident detail** | The fused-timeline spine renders: auth → whoami → beacon. Point at each node. | "Watch the fusion. 15:32:16 — an NTLM login to C553. Three seconds later, `whoami` runs on it. Five seconds after that, C553 beacons out to a new external address. Any signature tool waves all three through. Fused on one timeline, they're lateral movement, then discovery, then command-and-control. Compound score 0.94. Red-team confirmed. The signature baseline? Silent." |
| **1:20–2:00** | Same screen — ATT&CK card | Point at the three grounded techniques + predicted next + the respond gate. | "The reasoning runs on a *local* model — nothing leaves the box. It maps the incident to MITRE ATT&CK: T1021.006 Remote Services, T1057 Process Discovery, T1071 command-and-control — every technique grounded in retrieval, none hallucinated. It predicts the next tactic: exfiltration. And it recommends isolating C553 — behind a human gate." |
| **2:00–2:40** | Dashboard proof strip (or deck slide 5) | Zoom the four stats. | "Now the proof, measured on the real LANL red-team dataset. Behavioural recall: 0.79. The signature baseline on the same attacks: zero. On real data, nine of eleven red-team hosts fuse three sources into one high-confidence incident. Mean time to detect drops from weeks to under a minute. And we *measured* that threshold-tuning can't fix precision — which is exactly why we fuse across sources." |
| **2:40–3:00** | Terminal + deck slide 6 (sovereign) | **Cut the network** (disable Wi-Fi / `nmcli` off), refresh — dashboard + attribution still work. End on the close slide. | "Here's the differentiator. Classified national-infrastructure telemetry can't go to a foreign cloud API. So watch — I cut the network. Everything still runs: detection, correlation, ATT&CK attribution, all local. Prahari — the sentinel that connects the signals, before the breach." |

---

## Capture checklist
- Backend + frontend running; open `/` then `/incidents/inc-c553` in advance so the click is instant.
- Ollama up (`ollama list` shows `embeddinggemma`, `qwen2.5:7b`) if you demo live attribution; otherwise the dashboard serves the recorded attribution — either way it's grounded.
- For the network-cut moment, pre-load the pages so the browser doesn't need egress; the API is `localhost` only.
- Keep the deck (Artifact) open in a second tab for slides 1–2 and 6.

## The one-line pitch (if you only get 15 seconds)
> "Signature tools miss valid-credential APTs entirely — zero recall. Prahari fuses auth, process, and network behaviour into one ATT&CK-mapped incident, catches 79% of real red-team lateral movement, and runs fully air-gapped for national infrastructure."
