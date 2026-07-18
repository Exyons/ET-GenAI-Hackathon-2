import pytest

from prahari import config
from prahari.live import ipinfo
from prahari.live import settings as settings_store


@pytest.fixture(autouse=True)
def _isolate_runtime(monkeypatch, tmp_path):
    # tests must never make a real network call for IP enrichment …
    monkeypatch.setattr(config, "IP_ENRICH_URL", "")
    ipinfo.reset_cache()
    # … nor write settings into the repo's state dir
    monkeypatch.setattr(settings_store, "_PATH", tmp_path / "settings.json")
    settings_store.reset_cache()
    yield
    ipinfo.reset_cache()
    settings_store.reset_cache()
