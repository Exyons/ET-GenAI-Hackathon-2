# Offline threat intelligence

Prahari enriches network addresses **entirely offline** — no external lookups, so
it works in an air-gapped environment. It reads three optional datasets from this
directory (override with `THREATINTEL_DIR`):

| File | Format | Gives |
|---|---|---|
| `*.txt` blocklists | one IP or CIDR per line, `#` comments; filename = source | reputation (listed / clean) |
| `providers.json` | `[{"cidr": "...", "provider": "...", "type": "cloud\|cdn\|anonymizer"}]` | hosting provider |
| `geo.csv` | `cidr,country,city` | coarse geolocation |

The files here are a **seed** so the feature works out of the box. For production,
download real feeds once on a connected host and copy them in (as `.txt` files):

- **abuse.ch Feodo Tracker** — active C2 IPs
- **FireHOL Level 1 / Emerging Threats** — aggregated blocklists
- **Cloud provider ranges** — AWS `ip-ranges.json`, GCP, Azure, Cloudflare publish
  their prefixes; convert to `providers.json` entries
- **MaxMind GeoLite2** — export CIDR→country/city into `geo.csv`

Nothing is fetched at runtime; Prahari only reads what you place here. Restart the
API (or hit `/api/baseline/reset`) after changing the files — they are cached.
