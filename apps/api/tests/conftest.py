import shutil
from pathlib import Path

import pytest

from prahari import config
from prahari.live import ipinfo
from prahari.live import settings as settings_store
from prahari.live import threatintel

# Runtime artifacts that a live instance drops into threatintel/: downloaded
# feeds and the operator's own list. Tests must see a clean checkout, otherwise
# results depend on whether a feed happened to be refreshed — FireHOL level1,
# for instance, lists RFC1918 as bogon, which would mark internal IPs malicious.
_RUNTIME_INTEL = ("feed-*.txt", "operator.txt")


@pytest.fixture(autouse=True)
def _isolate_runtime(monkeypatch, tmp_path):
    # tests must never make a real network call for IP enrichment …
    monkeypatch.setattr(config, "IP_ENRICH_URL", "")
    ipinfo.reset_cache()
    # … nor write settings into the repo's state dir
    monkeypatch.setattr(settings_store, "_PATH", tmp_path / "settings.json")
    settings_store.reset_cache()

    # … nor read threat intel that a running instance downloaded
    seed = tmp_path / "threatintel"
    seed.mkdir()
    src = Path(config.THREATINTEL_DIR)
    if src.is_dir():
        runtime = {p.name for pat in _RUNTIME_INTEL for p in src.glob(pat)}
        for f in src.iterdir():
            if f.is_file() and f.name not in runtime:
                shutil.copy2(f, seed / f.name)
    monkeypatch.setattr(config, "THREATINTEL_DIR", str(seed))
    threatintel.reset_cache()

    yield
    ipinfo.reset_cache()
    settings_store.reset_cache()
    threatintel.reset_cache()
