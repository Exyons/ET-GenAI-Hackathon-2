from __future__ import annotations

import json
import threading
from pathlib import Path

from prahari import config

# Runtime-editable settings, persisted to STATE_DIR/settings.json. Env/config
# supplies the defaults; the Settings UI overrides them at runtime. The api_key is
# stored but never returned by the read path (see public()).
PROVIDERS = ("ollama", "ollama_cloud", "openai")

_PATH = Path(config.STATE_DIR) / "settings.json"
_lock = threading.RLock()
_cache: dict | None = None
_listeners: list = []


def _defaults() -> dict:
    return {
        "provider": "ollama",
        "base_url": config.OLLAMA_HOST,
        "api_key": "",
        "chat_model": config.CHAT_MODEL,
        "embed_model": config.EMBED_MODEL,
        "threatintel_feeds": list(config.THREATINTEL_FEEDS),
    }


def _load() -> dict:
    global _cache
    if _cache is None:
        d = _defaults()
        if _PATH.is_file():
            try:
                saved = json.loads(_PATH.read_text())
                d.update({k: v for k, v in saved.items() if k in d})
            except Exception:
                pass
        _cache = d
    return _cache


def on_change(fn) -> None:
    """Register a callback fired (with the changed keys) after every update — used
    to rebuild the attribution index when the embed model / provider changes."""
    _listeners.append(fn)


def get() -> dict:
    with _lock:
        return dict(_load())


def update(patch: dict) -> dict:
    with _lock:
        d = _load()
        changed = set()
        for k, v in patch.items():
            if k in d and v is not None and d[k] != v:
                d[k] = v
                changed.add(k)
        _PATH.parent.mkdir(parents=True, exist_ok=True)
        _PATH.write_text(json.dumps(d, indent=2))
        _cache = d
        result = dict(d)
    for fn in _listeners:  # outside the lock — listeners may read settings
        try:
            fn(changed)
        except Exception:
            pass
    return result


def public() -> dict:
    """Settings for GET responses: the key is masked, presence flagged."""
    d = get()
    d["api_key_set"] = bool(d["api_key"])
    d["api_key"] = ""
    d["providers"] = list(PROVIDERS)
    return d


def reset_cache() -> None:
    global _cache
    with _lock:
        _cache = None
