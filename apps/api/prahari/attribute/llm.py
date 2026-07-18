"""Provider-aware LLM access. Reads the runtime settings each call, so switching
provider / model in the Settings UI takes effect immediately. Supports Ollama
(local), Ollama Cloud (bearer), and any OpenAI-compatible endpoint."""
from __future__ import annotations

import httpx
import numpy as np

from prahari.attribute.ollama import ollama_chat, ollama_embed
from prahari.live import settings as settings_store


def _openai_base(base_url: str) -> str:
    url = base_url.rstrip("/")
    return url if url.endswith("/v1") else url + "/v1"


def _chat_openai(prompt: str, base_url: str, api_key: str, model: str) -> str:
    resp = httpx.post(
        f"{_openai_base(base_url)}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
        json={"model": model, "messages": [{"role": "user", "content": prompt}], "stream": False},
        timeout=180,
    )
    if resp.is_error:
        raise RuntimeError(f"openai {resp.status_code}: {resp.text[:200]}")
    return resp.json()["choices"][0]["message"]["content"]


def _embed_openai(texts: list[str], base_url: str, api_key: str, model: str) -> np.ndarray:
    resp = httpx.post(
        f"{_openai_base(base_url)}/embeddings",
        headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
        json={"model": model, "input": texts},
        timeout=120,
    )
    if resp.is_error:
        raise RuntimeError(f"openai {resp.status_code}: {resp.text[:200]}")
    return np.array([d["embedding"] for d in resp.json()["data"]], dtype=float)


def chat(prompt: str, s: dict | None = None) -> str:
    s = s or settings_store.get()
    if s["provider"] == "openai":
        return _chat_openai(prompt, s["base_url"], s["api_key"], s["chat_model"])
    # ollama local / cloud share one API; cloud just adds the bearer
    return ollama_chat(prompt, model=s["chat_model"], host=s["base_url"], api_key=s["api_key"] or None)


def embed(texts: list[str], s: dict | None = None) -> np.ndarray:
    s = s or settings_store.get()
    if s["provider"] == "openai":
        return _embed_openai(texts, s["base_url"], s["api_key"], s["embed_model"])
    return ollama_embed(texts, model=s["embed_model"], host=s["base_url"], api_key=s["api_key"] or None)


def test_connection(s: dict | None = None) -> dict:
    """Send a one-token prompt to verify the current provider/model works."""
    s = s or settings_store.get()
    try:
        reply = chat("Reply with the single word: ready.", s)
        return {"ok": True, "reply": reply.strip()[:200]}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}


def list_models(s: dict | None = None) -> dict:
    """Best-effort catalogue of models the configured provider exposes."""
    s = s or settings_store.get()
    try:
        if s["provider"] == "openai":
            resp = httpx.get(f"{_openai_base(s['base_url'])}/models",
                             headers={"Authorization": f"Bearer {s['api_key']}"} if s["api_key"] else {},
                             timeout=20)
            resp.raise_for_status()
            names = sorted(m["id"] for m in resp.json().get("data", []))
        else:
            resp = httpx.get(f"{s['base_url'].rstrip('/')}/api/tags",
                             headers={"Authorization": f"Bearer {s['api_key']}"} if s["api_key"] else {},
                             timeout=20)
            resp.raise_for_status()
            names = sorted(m["name"] for m in resp.json().get("models", []))
        return {"ok": True, "models": names}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}", "models": []}
