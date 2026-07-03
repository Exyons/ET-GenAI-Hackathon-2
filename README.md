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

See `docs/superpowers/specs/2026-07-03-prahari-cyber-resilience-design.md`.
