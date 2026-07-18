"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import {
  getFlaggedEvents, getIncidentEvents, getRecentEvents,
  type EventType, type TapeEvent,
} from "../lib/api";
import { subscribe } from "../lib/stream";
import { ExportMenu } from "./ExportMenu";
import { Icon } from "./Icon";
import { TapeList } from "./TapeList";
import { TelemetrySummary } from "./TelemetrySummary";
import { TopBar } from "./TopBar";

export type TelemetryView = "recent" | "flagged" | "incidents" | "high";
const RECENT_MAX = 400;

const TABS: { key: TelemetryView; label: string }[] = [
  { key: "recent", label: "RECENT" },
  { key: "flagged", label: "⚑ FLAGGED" },
  { key: "incidents", label: "INCIDENTS" },
  { key: "high", label: "HIGH CONF" },
];

const VIEW_HINT: Record<TelemetryView, string> = {
  recent: "raw tape",
  flagged: "sentinel-flagged in correlation window",
  incidents: "events inside correlated incidents",
  high: "events inside high-confidence incidents",
};

export function TelemetryConsole({ initialView }: { initialView: TelemetryView }) {
  const [view, setView] = useState<TelemetryView>(initialView);
  const [recent, setRecent] = useState<TapeEvent[]>([]);
  const [flagged, setFlagged] = useState<TapeEvent[]>([]);
  const [incEvents, setIncEvents] = useState<TapeEvent[]>([]);
  const [highEvents, setHighEvents] = useState<TapeEvent[]>([]);
  const [host, setHost] = useState("all");
  const [type, setType] = useState<"all" | EventType>("all");
  const [q, setQ] = useState("");
  const [summary, setSummary] = useState(false);

  useEffect(() => {
    const load = () => {
      getRecentEvents(RECENT_MAX).then((t) => setRecent([...t].reverse())).catch(() => {});
      getFlaggedEvents().then((t) => setFlagged([...t].reverse())).catch(() => {});
      getIncidentEvents(false).then((t) => setIncEvents([...t].reverse())).catch(() => {});
      getIncidentEvents(true).then((t) => setHighEvents([...t].reverse())).catch(() => {});
    };
    load();
    const unsub = subscribe((e) => {
      if (e.type === "telemetry") {
        setRecent((prev) => [...e.events.slice().reverse(), ...prev].slice(0, RECENT_MAX));
      }
    });
    const t = setInterval(load, 5000); // re-sync (window pruning, incident growth)
    return () => { unsub(); clearInterval(t); };
  }, []);

  const source =
    view === "recent" ? recent : view === "flagged" ? flagged : view === "incidents" ? incEvents : highEvents;
  const incidentCount = view === "incidents" || view === "high"
    ? new Set(source.map((e) => e.incident)).size
    : null;
  const hosts = useMemo(() => [...new Set(recent.map((e) => e.host))].sort(), [recent]);
  const needle = q.trim().toLowerCase();
  const shown = source.filter((e) =>
    (host === "all" || e.host === host)
    && (type === "all" || e.event_type === type)
    && (!needle
      || `${e.detail} ${e.actor ?? ""} ${e.host} ${e.source} ${e.phase} ${e.incident ?? ""}`
        .toLowerCase().includes(needle)),
  );

  return (
    <>
      <TopBar />
      <section className="panel tapefull">
        <h2>
          Live telemetry <span className="hint">— {VIEW_HINT[view]}</span>
          <span className="spacer" />
          <span className="hint mono">
            {incidentCount !== null ? `${incidentCount} incident${incidentCount === 1 ? "" : "s"} · ` : ""}
            {shown.length} / {source.length} events shown
          </span>
        </h2>
        <div className="toolbar">
          <div className="tabs" role="tablist">
            {TABS.map((t) => (
              <button key={t.key} type="button" role="tab" aria-selected={view === t.key}
                className={`tab mono${view === t.key ? " on" : ""}`} onClick={() => setView(t.key)}>
                {t.label}
              </button>
            ))}
          </div>
          <label className="filter mono">
            host
            <select value={host} onChange={(e) => setHost(e.target.value)}>
              <option value="all">all</option>
              {hosts.map((h) => <option key={h} value={h}>{h}</option>)}
            </select>
          </label>
          <label className="filter mono">
            type
            <select value={type} onChange={(e) => setType(e.target.value as "all" | EventType)}>
              <option value="all">all</option>
              <option value="auth">auth</option>
              <option value="process">process</option>
              <option value="network_flow">network</option>
            </select>
          </label>
          <input
            className="qfilter mono" type="search" placeholder="filter — command, user, host, phase…"
            value={q} onChange={(e) => setQ(e.target.value)}
          />
          <button type="button" className={`tab mono view-toggle${summary ? " on" : ""}`}
            aria-pressed={summary} onClick={() => setSummary((v) => !v)}>
            {summary ? <><Icon name="tape" /> TAPE</> : <><Icon name="summary" /> SUMMARY</>}
          </button>
          <ExportMenu />
        </div>
        {summary ? (
          <TelemetrySummary events={shown} />
        ) : (
          <div className="tapefull-scroll">
            <TapeList events={shown} />
          </div>
        )}
      </section>
      <Link href="/" className="back">◂ back to command view</Link>
    </>
  );
}
