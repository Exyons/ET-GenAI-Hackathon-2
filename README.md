# Prahari — AI-Driven Cyber Resilience for Critical National Infrastructure

ET AI Hackathon 2026 · Problem Statement 7. Behavioural (not signature) threat
detection that fuses auth + network + endpoint telemetry into one incident
timeline, maps it to MITRE ATT&CK with cited reasoning, and runs fully
air-gapped.

## Layout
- `apps/api` — FastAPI: ingestion, agents, replay (Python 3.14 + uv)
- `apps/web` — Next.js SOC command dashboard
- `data/`   — dataset download scripts (raw data git-ignored)
- `docs/superpowers/` — specs and plans

## Dev
- API tests: `cd apps/api && uv run pytest -v`
- Full stack: `docker-compose up`

## LLM attribution (Ollama, local & air-gapped)
Detection/correlation never needs the LLM — it only writes the ATT&CK
attribution (techniques + cited explanation + predicted next tactic).

```bash
curl -fsSL https://ollama.com/install.sh | sh   # or: pacman -S ollama
ollama pull qwen2.5:7b
ollama serve                                    # if not already a service
# then (re)start the API; defaults already point at it:
#   OLLAMA_HOST=http://localhost:11434  PRAHARI_CHAT_MODEL=qwen2.5:7b
```

Where the output shows up: the **ATT&CK attribution** panel on an incident's
detail page, the `ATT&CK MAPPED` pill on the incident board, the
**Attribute · LLM** stage in the dashboard's pipeline panel, and section 3 of
`/report`. Attribution runs on each new high-confidence incident and retries
every 60s, so starting Ollama *after* an incident fired still back-fills it.

See `docs/superpowers/specs/2026-07-03-prahari-cyber-resilience-design.md`.
