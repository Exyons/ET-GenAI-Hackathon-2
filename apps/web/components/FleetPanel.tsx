"use client";

import Link from "next/link";
import { useState } from "react";

import type { AgentSourceStatus, FleetHost, TapeEvent } from "../lib/api";
import { shortSource } from "../lib/format";
import { TapeList } from "./TapeList";

const OS_TAG: Record<FleetHost["os"], string> = { linux: "LNX", windows: "WIN", unknown: "—" };
const HOST_TAPE_MAX = 25;

const SOURCE_ORDER = ["auth", "process", "network"];

function agentEntries(agent: Record<string, AgentSourceStatus>): [string, AgentSourceStatus][] {
  return Object.entries(agent).sort(
    ([a], [b]) => SOURCE_ORDER.indexOf(a) - SOURCE_ORDER.indexOf(b),
  );
}

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

export function FleetPanel({ hosts, tape }: { hosts: FleetHost[]; tape: TapeEvent[] }) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const online = hosts.filter((h) => hostState(h.last_seen_s) === "online").length;

  return (
    <section className="panel">
      <h2>
        Sensor fleet
        <span className="spacer" />
        <Link href="/telemetry" className="hint mono navhint">full telemetry ▸</Link>
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
            const open = !collapsed[h.host];
            const hostEvents = tape.filter((e) => e.host === h.host).slice(0, HOST_TAPE_MAX);
            return (
              <div key={h.host} className="hostblock">
                <button
                  type="button"
                  className={`hostrow ${state}`}
                  onClick={() => setCollapsed((c) => ({ ...c, [h.host]: !c[h.host] }))}
                  aria-expanded={open}
                >
                  <span className={`statusdot ${state}`} title={state} />
                  <div className="who">
                    <div className="hostname mono">
                      {h.host}
                      <span className={`os ${h.os}`}>{OS_TAG[h.os]}</span>
                    </div>
                    <div className="srcs">
                      {h.agent
                        ? agentEntries(h.agent).map(([name, s]) => (
                            <span key={name} className={`src mono st-${s.state}`} title={s.detail || s.state}>
                              {name.toUpperCase()} {s.state === "error" ? "✕" : s.n}
                            </span>
                          ))
                        : h.sources.map((s) => (
                            <span key={s} className="src mono">{shortSource(s)}</span>
                          ))}
                    </div>
                    {h.agent && agentEntries(h.agent).filter(([, s]) => s.state === "error").map(([name, s]) => (
                      <div key={name} className="srcerr mono">{name}: {s.detail || "error"}</div>
                    ))}
                  </div>
                  <div className="tel mono">
                    <div className="epm">{h.epm}<span className="unit">/min</span></div>
                    <div className="seen">{lastSeenLabel(h.last_seen_s)}</div>
                  </div>
                  <span className="chev mono" aria-hidden>{open ? "▾" : "▸"}</span>
                </button>
                {open && (
                  <div className="hosttape">
                    <TapeList events={hostEvents} showHost={false} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
