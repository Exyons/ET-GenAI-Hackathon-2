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
# Debian/Ubuntu
sudo apt-get install -y auditd conntrack
# Arch / CachyOS / Manjaro
sudo pacman -S --needed audit conntrack-tools
sudo systemctl enable --now auditd

# capture process exec (both distros)
sudo auditctl -a always,exit -F arch=b64 -S execve
```

### Run
```bash
PRAHARI_URL=http://<prahari-host>:8000 \
PRAHARI_INGEST_TOKEN=<token> \
sudo -E python3 prahari_agent.py
```
Env: `PRAHARI_URL`, `PRAHARI_INGEST_TOKEN`, `PRAHARI_SOURCES=auth,process,network`,
`PRAHARI_BATCH_MAX`, `PRAHARI_FLUSH_SECONDS`, `PRAHARI_HEARTBEAT_SECONDS`.
Runs as root (journald audit + conntrack need it).

The agent heartbeats every 10s, so the machine appears in the dashboard's
**Sensor fleet** immediately — even before any event fires. A quiet desktop
generates almost no telemetry; to see events flow, `ssh localhost` (auth),
run a few commands with auditd active (process), or open outbound
connections (network).

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

## Response layer (containment)

The agent also polls `GET /api/actions/pending` for **approved** response actions
and executes them, reporting the result back. It is a **triple gate** — nothing
destructive runs unless all three hold:

1. an operator **approves** the recommendation in the dashboard (human gate), AND
2. approves it **armed** (not the default dry-run), AND
3. the agent was started with `PRAHARI_ALLOW_ARMED=true`.

Otherwise the agent reports the exact command it *would* run without touching the
host. Read-only playbooks (`snapshot`) always execute — they cannot harm.

```bash
# default: response on, armed execution OFF (dry-run only) — safe to run anywhere
sudo -E python3 prahari_agent.py

# opt in to real containment (nftables isolate/block, usermod lock, …):
PRAHARI_ALLOW_ARMED=true sudo -E python3 prahari_agent.py
```
Env: `PRAHARI_ACTIONS` (default true), `PRAHARI_ALLOW_ARMED` (default false),
`PRAHARI_ACTION_POLL_SECONDS`. Armed playbooks need root and `nftables`.
Playbooks: isolate_host, block_ip, disable_account, kill_process, snapshot —
all reversible except kill_process, via the **Revert** button.

## Tests
```bash
python -m pytest collectors/tests -q     # pure parser tests, no live system needed
```
