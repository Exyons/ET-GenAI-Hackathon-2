from __future__ import annotations

import ipaddress

# Offline (air-gapped) IP classification. No external lookups — everything is
# derived from the address itself, so it works with no network access.
_DOC_RANGES = {
    "192.0.2.0/24": "TEST-NET-1",
    "198.51.100.0/24": "TEST-NET-2",
    "203.0.113.0/24": "TEST-NET-3",
}
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def classify(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"klass": "unknown", "label": "Unrecognized address", "scope": "unknown"}

    if addr.is_loopback:
        return {"klass": "loopback", "label": "Loopback (this host)", "scope": "local"}
    if addr.is_link_local:
        return {"klass": "link_local", "label": "Link-local", "scope": "local"}
    if addr.is_multicast:
        return {"klass": "multicast", "label": "Multicast group", "scope": "local"}
    # documentation ranges before is_private — modern Python folds them into is_private
    if addr.version == 4:
        for net, name in _DOC_RANGES.items():
            if addr in ipaddress.ip_network(net):
                return {"klass": "documentation", "label": f"Documentation range ({name})", "scope": "external"}
        if addr in _CGNAT:
            return {"klass": "cgnat", "label": "Carrier-grade NAT (100.64/10)", "scope": "internal"}
    if addr.is_private:
        return {"klass": "private", "label": "Private / internal network (RFC 1918)", "scope": "internal"}
    return {"klass": "public", "label": "Public / external address", "scope": "external"}
