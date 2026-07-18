from __future__ import annotations

import json
import threading
import urllib.request

from prahari import config

# Online provider/geo lookup for public addresses the offline datasets don't cover.
# Air-leakage, not always-on: called only when offline enrichment is missing, one
# short-timeout request per address, then cached. Set IP_ENRICH_URL empty to keep
# it fully air-gapped. Response is parsed defensively so different services
# (ipwho.is, ipapi.co, ip-api.com …) all yield the same shape.
_cache: dict[str, dict] = {}
_lock = threading.Lock()


def _http_json(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "prahari-ipinfo/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - operator-configured URL
        return json.loads(r.read().decode("utf-8", "replace"))


def _parse(d: dict) -> dict:
    conn = d.get("connection") if isinstance(d.get("connection"), dict) else {}
    provider = (d.get("org") or conn.get("org") or conn.get("isp") or d.get("isp") or "").strip()
    asn = d.get("asn") or conn.get("asn")
    asn_s = ""
    if asn:
        asn_s = str(asn)
        if asn_s.isdigit():
            asn_s = "AS" + asn_s
    provider_type = asn_s or (conn.get("domain") or "")
    country = (d.get("country") or d.get("country_name") or "").strip()
    city = (d.get("city") or "").strip()
    return {"provider": provider, "provider_type": provider_type, "country": country, "city": city}


def lookup(ip: str, fetch=None) -> dict:
    """Return {provider, provider_type, country, city} for a public IP, or {} when
    disabled / unreachable / no data. Results (including empties) are cached."""
    url_t = config.IP_ENRICH_URL
    if not url_t:
        return {}
    with _lock:
        if ip in _cache:
            return _cache[ip]
    fetch = fetch or (lambda u: _http_json(u, config.IP_ENRICH_TIMEOUT))
    try:
        data = fetch(url_t.format(ip=ip))
        if isinstance(data, dict) and data.get("success") is False:
            res: dict = {}
        else:
            res = {k: v for k, v in _parse(data).items() if v} if isinstance(data, dict) else {}
    except Exception:
        res = {}
    with _lock:
        _cache[ip] = res
    return res


def reset_cache() -> None:
    with _lock:
        _cache.clear()
