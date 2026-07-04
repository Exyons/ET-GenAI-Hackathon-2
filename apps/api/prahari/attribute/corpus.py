from __future__ import annotations

import json
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
