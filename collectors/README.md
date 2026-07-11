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

## Windows (`prahari_agent.py`, same script)

Sources → `CanonicalEvent` (polled via `Get-WinEvent` every 3s):
- **auth** — Security 4624/4625 (logon success/failure; machine + service accounts filtered).
- **process** — Sysmon EventID 1 (process create); falls back to Security 4688 if Sysmon
  isn't installed (enable *Audit Process Creation* policy for 4688).
- **network** — Sysmon EventID 3 (network connection). Needs Sysmon.

### Install (optional but recommended: Sysmon)
```powershell
# in an elevated PowerShell
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip; .\Sysmon\Sysmon64.exe -accepteula -i
```

### Run
```powershell
# elevated PowerShell (reading the Security log requires admin)
$env:PRAHARI_URL = "http://<prahari-host>:8000"
$env:PRAHARI_INGEST_TOKEN = "<token>"
python prahari_agent.py
```
Without Sysmon, run auth-only or auth+process(4688): `$env:PRAHARI_SOURCES = "auth,process"`.
The agent picks `sources_windows.py` automatically via `platform.system()`.

## Tests
```bash
python -m pytest collectors/tests -q     # pure parser tests, no live system needed
```
