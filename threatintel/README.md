# Threat intelligence

Prahari enriches network addresses from datasets in this directory (override the
location with `THREATINTEL_DIR`):

| File | Format | Gives |
|---|---|---|
| `*.txt` blocklists | one IP or CIDR per line, `#` comments; filename = source | reputation (listed / clean) |
| `providers.json` | `[{"cidr": "...", "provider": "...", "type": "cloud\|cdn\|anonymizer"}]` | hosting provider |
| `geo.csv` | `cidr,country,city` | coarse geolocation |

The bundled files are a **seed** so the feature works out of the box, fully offline.

## Keeping blocklists fresh (feeds)

Reputation data goes stale fast, so Prahari can refresh blocklists on a schedule
instead of only reading static files. Configure feeds with env vars:

```
THREATINTEL_FEEDS=https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
THREATINTEL_REFRESH_HOURS=12
```

On startup and every `REFRESH_HOURS` the API downloads each feed into this
directory as `feed-<name>.txt` and re-reads it. Multiple feeds: comma-separate the
URLs. `GET /api/threatintel` shows per-feed status; `POST /api/threatintel/refresh`
forces an update now. **A feed that can't be reached is skipped, never fatal** —
set `THREATINTEL_FEEDS=` (empty) to run fully air-gapped on the bundled + operator
files. Fetched `feed-*.txt` files are git-ignored (runtime data).

## Setting your own blocklist

Two ways to add addresses you consider malicious:

1. **Drop a file** — any `.txt` here (one IP/CIDR per line) is loaded; the filename
   becomes the source label.
2. **From the UI** — the network-address detail popup has *Add to blocklist*, which
   appends to `operator.txt` (also git-ignored) via
   `POST /api/threatintel/blocklist {"ip": "...", "note": "..."}`.

Static file edits are cached — restart the API or hit `/api/baseline/reset` after
changing them. Feed refreshes, `/refresh`, and operator adds reset the cache
automatically.

Good real-world feeds to point at: **abuse.ch Feodo Tracker** (active C2),
**FireHOL Level 1 / Emerging Threats** (aggregated), plus cloud provider ranges
(AWS `ip-ranges.json`, GCP, Azure, Cloudflare) for `providers.json` and **MaxMind
GeoLite2** for `geo.csv`.
