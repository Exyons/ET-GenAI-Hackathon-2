export function clock(iso: string): string {
  return new Date(iso).toISOString().slice(11, 19);
}

export function compact(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 10_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

// Age relative to `now` (ms). Returns null when now is unknown (pre-hydration)
// or the timestamp is older than a day (scenario replays carry 2017 dates).
export function age(iso: string, now: number | null): string | null {
  if (now === null) return null;
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return null;
}

export function mmss(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

export const SOURCE_SHORT: Record<string, string> = {
  lanl: "AUTH",
  otrf: "SYSMON",
  cicids: "NETFLOW",
  sysmon: "SYSMON",
  conntrack: "NETFLOW",
  "linux-auth": "SSHD",
  "linux-audit": "AUDITD",
  "linux-conntrack": "CONNTRACK",
  "windows-security": "WINSEC",
  "windows-sysmon": "SYSMON",
};

export const shortSource = (s: string) => SOURCE_SHORT[s] ?? s.toUpperCase();
