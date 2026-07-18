import prahari.live.ipinfo as ipinfo
from prahari import config


def test_parse_ipwhois_shape(monkeypatch):
    monkeypatch.setattr(config, "IP_ENRICH_URL", "https://x/{ip}")
    ipinfo.reset_cache()
    body = {"success": True, "country": "United States", "city": "Mountain View",
            "connection": {"asn": 15169, "org": "Google LLC", "isp": "Google LLC"}}
    r = ipinfo.lookup("8.8.8.8", fetch=lambda u: body)
    assert r["provider"] == "Google LLC" and r["provider_type"] == "AS15169"
    assert r["country"] == "United States" and r["city"] == "Mountain View"


def test_parse_flat_shape(monkeypatch):
    monkeypatch.setattr(config, "IP_ENRICH_URL", "https://x/{ip}")
    ipinfo.reset_cache()
    body = {"org": "Cloudflare, Inc.", "asn": "AS13335", "country_name": "US", "city": "SF"}
    r = ipinfo.lookup("1.1.1.1", fetch=lambda u: body)
    assert r["provider"] == "Cloudflare, Inc." and r["provider_type"] == "AS13335"
    assert r["country"] == "US" and r["city"] == "SF"


def test_disabled_and_unreachable(monkeypatch):
    monkeypatch.setattr(config, "IP_ENRICH_URL", "")
    ipinfo.reset_cache()
    assert ipinfo.lookup("8.8.8.8", fetch=lambda u: {"org": "x"}) == {}  # disabled → no call

    monkeypatch.setattr(config, "IP_ENRICH_URL", "https://x/{ip}")
    ipinfo.reset_cache()

    def boom(u):
        raise OSError("refused")

    assert ipinfo.lookup("9.9.9.9", fetch=boom) == {}  # unreachable → empty, not fatal


def test_cache_avoids_second_fetch(monkeypatch):
    monkeypatch.setattr(config, "IP_ENRICH_URL", "https://x/{ip}")
    ipinfo.reset_cache()
    calls = {"n": 0}

    def once(u):
        calls["n"] += 1
        return {"org": "ACME", "asn": 64500}

    ipinfo.lookup("203.0.113.1", fetch=once)
    ipinfo.lookup("203.0.113.1", fetch=once)
    assert calls["n"] == 1
