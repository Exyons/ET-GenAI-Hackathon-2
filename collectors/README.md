# Prahari collectors

Push agents that tail real telemetry and stream it to Prahari's `/api/ingest`.
**Stdlib only** — no pip install on the monitored host.

## Linux (`prahari_agent.py`)

Sources → `CanonicalEvent`:
- **auth** — `journalctl -f -o json -u ssh` (SSH accepted/failed).
- **process** — `journalctl _TRANSPORT=audit` execve (needs `auditd` with an execve rule).
- **network** — `conntrack -E -e NEW` outbound flows (needs `conntrack-tools`).

### Install
```bash
sudo apt-get install -y auditd conntrack     # Debian/Ubuntu
sudo auditctl -a always,exit -F arch=b64 -S execve   # capture process exec
```

### Run
```bash
PRAHARI_URL=http://<prahari-host>:8000 \
PRAHARI_INGEST_TOKEN=<token> \
sudo -E python3 prahari_agent.py
```
Env: `PRAHARI_URL`, `PRAHARI_INGEST_TOKEN`, `PRAHARI_SOURCES=auth,process,network`,
`PRAHARI_BATCH_MAX`, `PRAHARI_FLUSH_SECONDS`. Runs as root (journald audit + conntrack need it).

### Reaching Prahari from a cloud VM
Prahari's `/api/ingest` must be reachable from the VM. Either **run Prahari on the VM**, or
tunnel it: `tailscale` (private mesh) or `ngrok http 8000` — always keep the bearer token set so
random hosts can't POST.

If `auditd` isn't available, run auth + network only: `PRAHARI_SOURCES=auth,network`.

## Windows (L4, follow-on)
`sources_windows.py` will read Sysmon EventID 1/3 + Security 4624/4625 via `Get-WinEvent`.

## Tests
```bash
python -m pytest collectors/tests -q     # pure parser tests, no live system needed
```
