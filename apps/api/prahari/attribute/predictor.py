from __future__ import annotations

from collections import Counter, defaultdict

ATTACK_TACTIC_PRIOR = [
    ["initial-access", "execution", "discovery", "lateral-movement",
     "collection", "command-and-control", "exfiltration"],
    ["lateral-movement", "discovery", "collection", "exfiltration"],
    ["execution", "discovery", "lateral-movement", "command-and-control"],
]


class TacticPredictor:
    def __init__(self) -> None:
        self._trans: dict[str, Counter] = defaultdict(Counter)

    def fit(self, sequences: list[list[str]]) -> "TacticPredictor":
        for seq in sequences:
            for a, b in zip(seq, seq[1:]):
                self._trans[a][b] += 1
        return self

    def predict_next(self, current: str, k: int = 3) -> list[tuple[str, float]]:
        counts = self._trans.get(current)
        if not counts:
            return []
        total = sum(counts.values())
        ranked = counts.most_common(k)
        return [(tactic, n / total) for tactic, n in ranked]
