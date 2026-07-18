import pytest

from prahari import config
from prahari.live import ipinfo


@pytest.fixture(autouse=True)
def _no_online_ip_enrichment(monkeypatch):
    # tests must never make a real network call for IP enrichment
    monkeypatch.setattr(config, "IP_ENRICH_URL", "")
    ipinfo.reset_cache()
    yield
    ipinfo.reset_cache()
