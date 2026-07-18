from __future__ import annotations

from prahari import config
from prahari.live import settings as settings_store
from prahari.live.actions import ActionStore
from prahari.live.attribution import build_attribute_fn
from prahari.live.bus import EventBus
from prahari.live.pipeline import LivePipeline

# Shared, app-lifetime singletons. Imported by api.routes and main.py.
bus = EventBus()
action_store = ActionStore(bus)

# Attribution is built lazily on the first high-confidence incident so importing this
# module (at app startup) never touches Ollama. If Ollama/corpus is unavailable the
# pipeline's own try/except skips attribution without breaking detection.
_attr_fn = None


def _attribute(incident):
    global _attr_fn
    if _attr_fn is None:
        _attr_fn = build_attribute_fn(config.CORPUS_PATH)
    return _attr_fn(incident)


def _on_settings_change(changed: set) -> None:
    # the corpus is embedded once when the attribution fn is built, so a change to
    # the embed model / provider needs a rebuild; drop it and it re-embeds lazily
    global _attr_fn
    if changed & {"provider", "embed_model"}:
        _attr_fn = None


settings_store.on_change(_on_settings_change)


pipeline = LivePipeline(
    warmup_seconds=config.WARMUP_SECONDS,
    window_seconds=config.CORR_WINDOW_SECONDS,
    quantile=config.ANOMALY_QUANTILE,
    attribute_fn=_attribute,
    bus=bus,
    state_dir=config.STATE_DIR,
    action_store=action_store,
)
