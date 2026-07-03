# Datasets (not committed)

Real data lands in `data/raw/` (git-ignored). The app never downloads — only these scripts do.

| Dataset | File(s) | Source |
|---|---|---|
| LANL Auth | `auth.txt`, `redteam.txt` | https://csr.lanl.gov/data/cyber1/ |
| CICIDS2017 | `*.csv` | https://www.unb.ca/cic/datasets/ids-2017.html |
| OTRF Security-Datasets (Sysmon) | `*.jsonl` | https://github.com/OTRF/Security-Datasets |

Run `bash data/download.sh` after placing credentials/accepting dataset terms.
