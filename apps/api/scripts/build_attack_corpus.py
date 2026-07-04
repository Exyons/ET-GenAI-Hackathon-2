"""Build the trimmed ATT&CK technique corpus from MITRE STIX. Manual (network).

Usage: cd apps/api && uv run python scripts/build_attack_corpus.py
Writes corpus/attack_techniques.json (committed).
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[3]
STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def main() -> None:
    data = httpx.get(STIX_URL, timeout=120, follow_redirects=True).json()
    out = []
    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(
            (r for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext or not ext.get("external_id", "").startswith("T"):
            continue
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        desc = (obj.get("description") or "").split("\n")[0][:600]
        out.append({
            "id": ext["external_id"], "name": obj.get("name", ""),
            "tactics": tactics, "description": desc,
        })
    out.sort(key=lambda d: d["id"])
    dest = ROOT / "corpus/attack_techniques.json"
    dest.parent.mkdir(exist_ok=True)
    dest.write_text(json.dumps(out, indent=1))
    print(f"wrote {len(out)} techniques to {dest}")


if __name__ == "__main__":
    main()
