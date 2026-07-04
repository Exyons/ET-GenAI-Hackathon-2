from __future__ import annotations

from collections.abc import Callable

import numpy as np

from prahari.attribute.corpus import TechniqueDoc


def _l2norm(m: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(m, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return m / norms


class Retriever:
    def __init__(self, embed_fn: Callable[[list[str]], np.ndarray]) -> None:
        self.embed_fn = embed_fn
        self.corpus: list[TechniqueDoc] = []
        self._matrix = np.empty((0, 0))

    def fit(self, corpus: list[TechniqueDoc]) -> "Retriever":
        self.corpus = list(corpus)
        embeddings = np.asarray(self.embed_fn([d.text() for d in self.corpus]), dtype=float)
        self._matrix = _l2norm(embeddings)
        return self

    def retrieve(self, query: str, k: int = 5) -> list[tuple[TechniqueDoc, float]]:
        q = np.asarray(self.embed_fn([query]), dtype=float)
        q = _l2norm(q)[0]
        scores = self._matrix @ q
        order = np.argsort(scores)[::-1][:k]
        return [(self.corpus[i], float(scores[i])) for i in order]
