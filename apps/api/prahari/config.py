from __future__ import annotations

import os
import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]


def load_dotenv(path: Path) -> None:
    """Minimal stdlib .env loader: KEY=VALUE lines, # comments, quotes optional.
    Real environment variables always win (setdefault)."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = re.split(r"\s+#", value, maxsplit=1)[0].strip().strip("'\"")
        os.environ.setdefault(key.strip(), value)


# .env at the repo root (as documented in .env.example), then next to the API app
load_dotenv(_REPO_ROOT / ".env")
load_dotenv(Path.cwd() / ".env")

# Live pipeline / ingest configuration. Plain env reads — no new deps.
INGEST_TOKEN = os.environ.get("PRAHARI_INGEST_TOKEN", "dev-token")
WARMUP_SECONDS = int(os.environ.get("WARMUP_SECONDS", "180"))
CORR_WINDOW_SECONDS = int(os.environ.get("CORR_WINDOW_SECONDS", "300"))
ANOMALY_QUANTILE = float(os.environ.get("ANOMALY_QUANTILE", "0.99"))
STATE_DIR = os.environ.get("STATE_DIR", "./state")

# Attribution (local, air-gapped by default). Chat writes the explanation;
# the embed model powers ATT&CK retrieval — both must be pulled in Ollama.
CHAT_MODEL = os.environ.get("PRAHARI_CHAT_MODEL", "qwen2.5:7b")
EMBED_MODEL = os.environ.get("PRAHARI_EMBED_MODEL", "embeddinggemma")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
CORPUS_PATH = os.environ.get("CORPUS_PATH", str(_REPO_ROOT / "corpus" / "attack_techniques.json"))

# Threat-intel datasets (blocklists, provider ranges, geo) — see threatintel/README.md.
# The bundled files always load; on top of that, blocklist FEEDS are refreshed on a
# schedule so reputation data doesn't go stale. Set THREATINTEL_FEEDS empty to run
# fully offline — the bundled + operator files still work. A feed that can't be
# reached is skipped, never fatal, so an air-gapped box degrades gracefully.
THREATINTEL_DIR = os.environ.get("THREATINTEL_DIR", str(_REPO_ROOT / "threatintel"))
THREATINTEL_FEEDS = [
    u.strip() for u in os.environ.get(
        "THREATINTEL_FEEDS",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    ).split(",") if u.strip()
]
THREATINTEL_REFRESH_HOURS = float(os.environ.get("THREATINTEL_REFRESH_HOURS", "12"))
