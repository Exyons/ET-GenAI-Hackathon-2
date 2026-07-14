"""Thin Ollama HTTP adapters. Not unit-tested (require the live daemon)."""
from __future__ import annotations

import httpx
import numpy as np

DEFAULT_HOST = "http://localhost:11434"


def _raise_with_body(resp: httpx.Response) -> None:
    # ollama puts the useful part ("model 'x' not found, try pulling it") in the
    # body; raise_for_status would hide it behind a bare status code
    if resp.is_error:
        raise RuntimeError(f"ollama {resp.status_code}: {resp.text[:200]}")


def ollama_embed(
    texts: list[str], model: str = "embeddinggemma", host: str = DEFAULT_HOST
) -> np.ndarray:
    resp = httpx.post(f"{host}/api/embed", json={"model": model, "input": texts}, timeout=120)
    _raise_with_body(resp)
    return np.array(resp.json()["embeddings"], dtype=float)


def ollama_chat(
    prompt: str, model: str = "qwen3.5:cloud", host: str = DEFAULT_HOST
) -> str:
    resp = httpx.post(
        f"{host}/api/chat",
        json={"model": model, "messages": [{"role": "user", "content": prompt}], "stream": False},
        timeout=180,
    )
    _raise_with_body(resp)
    return resp.json()["message"]["content"]
