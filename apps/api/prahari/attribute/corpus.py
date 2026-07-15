from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TechniqueDoc:
    id: str
    name: str
    tactics: list[str]
    description: str

    def text(self) -> str:
        tac = ", ".join(self.tactics)
        return f"{self.id} {self.name}. Tactics: {tac}. {self.description}"


def load_corpus(path: str | Path) -> list[TechniqueDoc]:
    raw = json.loads(Path(path).read_text())
    return [
        TechniqueDoc(
            id=d["id"], name=d["name"],
            tactics=list(d.get("tactics", [])), description=d.get("description", ""),
        )
        for d in raw
    ]


_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")   # [name](url) → name
_CITATION = re.compile(r"\(Citation:[^)]*\)")


def short_description(text: str, max_len: int = 280) -> str:
    """First 1-2 sentences of an ATT&CK description — enough to say what the
    technique is, without dumping the full doctrine paragraph or its markup."""
    text = _CITATION.sub("", _MD_LINK.sub(r"\1", text))
    text = re.sub(r"\s+", " ", text).strip()
    parts = re.split(r"(?<=[.!?])\s+", text)
    out = " ".join(parts[:2]).strip()
    return (out[: max_len].rstrip() + "…") if len(out) > max_len else out


_DESC_CACHE: dict[str, dict[str, str]] = {}


def descriptions(path: str | Path) -> dict[str, str]:
    """id → short description, cached. Missing/unreadable corpus → empty map."""
    key = str(path)
    if key not in _DESC_CACHE:
        try:
            _DESC_CACHE[key] = {d.id: short_description(d.description) for d in load_corpus(path)}
        except Exception:
            _DESC_CACHE[key] = {}
    return _DESC_CACHE[key]
