import type { FleetHost } from "../lib/api";
import { shortSource } from "../lib/format";

const OS_TAG: Record<FleetHost["os"], string> = { linux: "LNX", windows: "WIN", unknown: "—" };

function hostState(lastSeen: number | null): "online" | "stale" | "offline" {
  if (lastSeen === null) return "offline";
  if (lastSeen < 15) return "online";
  if (lastSeen < 60) return "stale";
  return "offline";
}

function lastSeenLabel(s: number | null): string {
  if (s === null) return "never";
  if (s < 1) return "now";
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  return `${Math.floor(s / 3600)}h`;
}

export function FleetPanel({ hosts }: { hosts: FleetHost[] }) {
  const online = hosts.filter((h) => hostState(h.last_seen_s) === "online").length;

  return (
    <section className="panel">
      <h2>
        Sensor fleet
        <span className="spacer" />
        <span className="hint mono">{online}/{hosts.length} reporting</span>
      </h2>
      {hosts.length === 0 ? (
        <div className="empty">
          <p>No machines reporting yet.</p>
          <p className="mono dim">run collectors/prahari_agent.py on a Linux or Windows box</p>
        </div>
      ) : (
        <div className="fleet">
          {hosts.map((h) => {
            const state = hostState(h.last_seen_s);
            return (
              <div key={h.host} className={`hostrow ${state}`}>
                <span className={`statusdot ${state}`} title={state} />
                <div className="who">
                  <div className="hostname mono">
                    {h.host}
                    <span className={`os ${h.os}`}>{OS_TAG[h.os]}</span>
                  </div>
                  <div className="srcs">
                    {h.sources.map((s) => (
                      <span key={s} className="src mono">{shortSource(s)}</span>
                    ))}
                  </div>
                </div>
                <div className="mix mono" title="auth · process · network events">
                  <span><i className="swatch s-auth" />{h.by_type.auth ?? 0}</span>
                  <span><i className="swatch s-proc" />{h.by_type.process ?? 0}</span>
                  <span><i className="swatch s-net" />{h.by_type.network_flow ?? 0}</span>
                </div>
                <div className="tel mono">
                  <div className="epm">{h.epm}<span className="unit">/min</span></div>
                  <div className="seen">{lastSeenLabel(h.last_seen_s)}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
