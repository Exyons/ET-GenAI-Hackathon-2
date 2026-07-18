"use client";

import { useEffect, useRef, useState } from "react";

import { getNetworkDetail, type TapeEvent } from "../lib/api";
import { IpChip } from "./IpChip";

type Enrichment = { provider: string; provider_type: string; scope: string; klass: string; severity: string };
const SCOPE_TAG: Record<string, { label: string; cls: string }> = {
  bad: { label: "malicious", cls: "bad" },
  good: { label: "internal", cls: "good" },
  neutral: { label: "public", cls: "neutral" },
};

// Fetches offline/online enrichment for the addresses shown in the table, cached
// per IP so it survives the live re-renders and never re-fetches the same address.
function useEnrichment(ips: string[]): Record<string, Enrichment> {
  const [cache, setCache] = useState<Record<string, Enrichment>>({});
  const requested = useRef<Set<string>>(new Set());
  const key = ips.join(",");
  useEffect(() => {
    for (const ip of ips) {
      if (requested.current.has(ip)) continue;
      requested.current.add(ip);
      getNetworkDetail(ip)
        .then((d) => setCache((c) => ({ ...c, [ip]: {
          provider: d.provider, provider_type: d.provider_type,
          scope: d.scope, klass: d.klass, severity: d.severity,
        } })))
        .catch(() => { requested.current.delete(ip); });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return cache;
}

// Live visual summary of whatever slice of telemetry is currently in view — reads
// the same event array the tape renders, so it updates in place as events stream.
// Charts over scrolling text: the eye gets the shape of the traffic at a glance.

const TYPE_META: { key: string; label: string; color: string }[] = [
  { key: "auth", label: "Auth", color: "#3987e5" },
  { key: "process", label: "Process", color: "#c98500" },
  { key: "network_flow", label: "Network", color: "#199e70" },
];

function count<T>(items: T[], key: (t: T) => string): Map<string, number> {
  const m = new Map<string, number>();
  for (const it of items) m.set(key(it), (m.get(key(it)) ?? 0) + 1);
  return m;
}

function Donut({ events }: { events: TapeEvent[] }) {
  const byType = count(events, (e) => e.event_type);
  const segs = TYPE_META.map((t) => ({ ...t, n: byType.get(t.key) ?? 0 }));
  const total = segs.reduce((a, s) => a + s.n, 0);
  const R = 54, C = 2 * Math.PI * R;
  let offset = 0;

  return (
    <div className="tsum-donut">
      <svg viewBox="0 0 140 140" role="img" aria-label="Events by type">
        <circle cx="70" cy="70" r={R} fill="none" stroke="var(--line)" strokeWidth="18" />
        {total > 0 && segs.filter((s) => s.n > 0).map((s) => {
          const frac = s.n / total;
          // 2px surface gap between arcs (skip when a segment is the whole ring)
          const gap = frac < 1 ? 2 : 0;
          const dash = Math.max(0, frac * C - gap);
          const el = (
            <circle key={s.key} cx="70" cy="70" r={R} fill="none" stroke={s.color} strokeWidth="18"
              strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={-offset}
              transform="rotate(-90 70 70)" />
          );
          offset += frac * C;
          return el;
        })}
        <text x="70" y="66" textAnchor="middle" className="tsum-donut-n">{total}</text>
        <text x="70" y="83" textAnchor="middle" className="tsum-donut-l">events</text>
      </svg>
      <div className="tsum-legend">
        {segs.map((s) => (
          <div key={s.key} className="tsum-leg">
            <i style={{ background: s.color }} />
            <span className="k">{s.label}</span>
            <span className="v mono">{s.n}</span>
            <span className="p mono">{total ? Math.round((s.n / total) * 100) : 0}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Bars({ title, data, color }: { title: string; data: [string, number][]; color: string }) {
  const max = Math.max(1, ...data.map(([, v]) => v));
  return (
    <div className="tsum-bars">
      <div className="tsum-h">{title}</div>
      {data.length === 0 ? <div className="mono dim tsum-none">no data</div> : data.map(([k, v]) => (
        <div key={k} className="tsum-bar">
          <span className="bk mono">{k}</span>
          <span className="bt"><span className="bf" style={{ width: `${(v / max) * 100}%`, background: color }} /></span>
          <span className="bn mono">{v}</span>
        </div>
      ))}
    </div>
  );
}

export function TelemetrySummary({ events }: { events: TapeEvent[] }) {
  const total = events.length;
  const flagged = events.filter((e) => e.flagged).length;
  const net = events.filter((e) => e.event_type === "network_flow").length;
  const incidents = new Set(events.map((e) => e.incident).filter(Boolean)).size;
  const hosts = count(events, (e) => e.host);
  const sources = count(events, (e) => e.source);
  const dstIps = count(events.filter((e) => e.dst_ip), (e) => e.dst_ip as string);

  const topHosts = [...hosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  const topSources = [...sources.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  const topIps = [...dstIps.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  const enrich = useEnrichment(topIps.map(([ip]) => ip));

  const tiles: { k: string; v: string | number; cls?: string }[] = [
    { k: "events in view", v: total },
    { k: "flagged", v: flagged, cls: flagged ? "bad" : "" },
    { k: "incidents", v: incidents, cls: incidents ? "bad" : "" },
    { k: "hosts", v: hosts.size },
    { k: "sources", v: sources.size },
    { k: "network flows", v: net },
  ];

  return (
    <div className="tsum">
      <div className="tsum-tiles">
        {tiles.map((t) => (
          <div key={t.k} className={`tsum-tile ${t.cls ?? ""}`}>
            <div className="tv mono">{t.v}</div>
            <div className="tk">{t.k}</div>
          </div>
        ))}
      </div>

      <div className="tsum-grid">
        <div className="tsum-card">
          <div className="tsum-h">Events by type</div>
          <Donut events={events} />
        </div>
        <div className="tsum-card">
          <Bars title="Top hosts by volume" data={topHosts} color="#3987e5" />
        </div>
        <div className="tsum-card">
          <Bars title="Events by source" data={topSources} color="#6a4ca8" />
        </div>
      </div>

      <div className="tsum-card">
        <div className="tsum-h">Most-contacted addresses</div>
        {topIps.length === 0 ? (
          <div className="mono dim tsum-none">no network destinations in this view</div>
        ) : (
          <table className="tsum-table">
            <thead><tr><th>Address</th><th>Provider</th><th>Scope</th><th>Connections</th><th>Share</th></tr></thead>
            <tbody>
              {topIps.map(([ip, n]) => {
                const e = enrich[ip];
                const tag = e ? SCOPE_TAG[e.severity] : undefined;
                return (
                  <tr key={ip}>
                    <td><IpChip ip={ip} /></td>
                    <td className="mono tsum-prov">{e?.provider || (e ? "—" : "…")}{e?.provider_type ? ` · ${e.provider_type}` : ""}</td>
                    <td>{tag ? <span className={`tsum-scope ${tag.cls}`}>{tag.label}</span> : <span className="mono dim">…</span>}</td>
                    <td className="mono">{n}</td>
                    <td>
                      <span className="tsum-inline-bar">
                        <span style={{ width: `${(n / topIps[0][1]) * 100}%` }} />
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
