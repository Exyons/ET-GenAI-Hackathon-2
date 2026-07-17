from __future__ import annotations

import csv
import ipaddress
import json
from pathlib import Path

from prahari import config

# Offline IP enrichment: hosting provider, coarse geo, and blocklist reputation —
# all from local datasets (threatintel/), never a live lookup. Loaded once, cached.
_store: "_Store | None" = None


class _Store:
    def __init__(self) -> None:
        self.block: list[tuple] = []      # (network, source)
        self.providers: list[tuple] = []  # (network, {"provider","type"})
        self.geo: list[tuple] = []        # (network, {"country","city"})


def _networks(lines) -> list:
    out = []
    for ln in lines:
        ln = ln.split("#", 1)[0].strip()
        if not ln:
            continue
        try:
            out.append(ipaddress.ip_network(ln, strict=False))
        except ValueError:
            pass
    return out


def _load(d: Path) -> _Store:
    s = _Store()
    if not d.is_dir():
        return s
    for f in sorted(d.glob("*.txt")):
        for net in _networks(f.read_text().splitlines()):
            s.block.append((net, f.stem))
    pj = d / "providers.json"
    if pj.is_file():
        try:
            for e in json.loads(pj.read_text()):
                s.providers.append((ipaddress.ip_network(e["cidr"], strict=False),
                                    {"provider": e.get("provider", ""), "type": e.get("type", "")}))
        except Exception:
            pass
    gc = d / "geo.csv"
    if gc.is_file():
        try:
            for row in csv.DictReader(gc.read_text().splitlines()):
                s.geo.append((ipaddress.ip_network(row["cidr"], strict=False),
                              {"country": row.get("country", ""), "city": row.get("city", "")}))
        except Exception:
            pass
    return s


def _get() -> _Store:
    global _store
    if _store is None:
        _store = _load(Path(config.THREATINTEL_DIR))
    return _store


def reset_cache() -> None:
    global _store
    _store = None


def _match(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    return [meta for net, meta in nets if addr in net]


def enrich(ip: str) -> dict:
    s = _get()
    sources = sorted({src for src in _match(ip, s.block)})
    prov = _match(ip, s.providers)
    geo = _match(ip, s.geo)
    return {
        "provider": prov[0]["provider"] if prov else "",
        "provider_type": prov[0]["type"] if prov else "",
        "country": geo[0]["country"] if geo else "",
        "city": geo[0]["city"] if geo else "",
        "reputation": {"listed": bool(sources), "sources": sources},
    }


def context_for(ip: str) -> str:
    """One-line context for the LLM prompt, e.g.
    'Amazon CloudFront/cdn, Seattle, US, ON BLOCKLIST: blocklist'."""
    e = enrich(ip)
    bits = []
    if e["provider"]:
        bits.append(e["provider"] + (f"/{e['provider_type']}" if e["provider_type"] else ""))
    loc = ", ".join(x for x in (e["city"], e["country"]) if x)
    if loc:
        bits.append(loc)
    if e["reputation"]["listed"]:
        bits.append("ON BLOCKLIST: " + ", ".join(e["reputation"]["sources"]))
    return ", ".join(bits)


def stats() -> dict:
    s = _get()
    sources = sorted({src for _, src in s.block})
    return {"blocklist_entries": len(s.block), "blocklist_sources": sources,
            "provider_ranges": len(s.providers), "geo_ranges": len(s.geo)}


def add_blocklist_entry(cidr: str, note: str = "", source: str = "operator") -> None:
    """Append an operator-supplied address/CIDR to a local blocklist file and
    refresh the cache. This is how a user sets their own blacklist — the entry
    persists in threatintel/<source>.txt and survives restarts."""
    net = ipaddress.ip_network(cidr.strip(), strict=False)  # raises ValueError if bad
    d = Path(config.THREATINTEL_DIR)
    d.mkdir(parents=True, exist_ok=True)
    line = str(net) + (f"  # {note.strip()}" if note.strip() else "")
    f = d / f"{source}.txt"
    existing = f.read_text().splitlines() if f.is_file() else []
    if any(ln.split("#", 1)[0].strip() == str(net) for ln in existing):
        return  # already listed — no duplicate
    with f.open("a") as fh:
        fh.write(line + "\n")
    reset_cache()
