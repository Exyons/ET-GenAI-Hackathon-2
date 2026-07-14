"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { getFlaggedEvents, getRecentEvents, type EventType, type TapeEvent } from "../lib/api";
import { subscribe } from "../lib/stream";
import { TapeList } from "./TapeList";
import { TopBar } from "./TopBar";

export type TelemetryView = "recent" | "flagged";
const RECENT_MAX = 400;

export function TelemetryConsole({ initialView }: { initialView: TelemetryView }) {
  const [view, setView] = useState<TelemetryView>(initialView);
  const [recent, setRecent] = useState<TapeEvent[]>([]);
  const [flagged, setFlagged] = useState<TapeEvent[]>([]);
  const [host, setHost] = useState("all");
  const [type, setType] = useState<"all" | EventType>("all");

  useEffect(() => {
    const load = () => {
      getRecentEvents(RECENT_MAX).then((t) => setRecent([...t].reverse())).catch(() => {});
      getFlaggedEvents().then((t) => setFlagged([...t].reverse())).catch(() => {});
    };
    load();
    const unsub = subscribe((e) => {
      if (e.type === "telemetry") {
        setRecent((prev) => [...e.events.slice().reverse(), ...prev].slice(0, RECENT_MAX));
      }
    });
    const t = setInterval(load, 5000); // re-sync (window pruning, missed frames)
    return () => { unsub(); clearInterval(t); };
  }, []);

  const source = view === "recent" ? recent : flagged;
  const hosts = useMemo(() => [...new Set(recent.map((e) => e.host))].sort(), [recent]);
  const shown = source.filter(
    (e) => (host === "all" || e.host === host) && (type === "all" || e.event_type === type),
  );

  return (
    <>
      <TopBar />
      <section className="panel tapefull">
        <h2>
          Live telemetry
          <span className="hint">
            — {view === "recent" ? `last ${recent.length} events` : `${flagged.length} flagged in correlation window`}
          </span>
          <span className="spacer" />
          <span className="hint mono">{shown.length} shown</span>
        </h2>
        <div className="toolbar">
          <div className="tabs" role="tablist">
            <button type="button" role="tab" aria-selected={view === "recent"}
              className={`tab mono${view === "recent" ? " on" : ""}`} onClick={() => setView("recent")}>
              RECENT
            </button>
            <button type="button" role="tab" aria-selected={view === "flagged"}
              className={`tab mono${view === "flagged" ? " on" : ""}`} onClick={() => setView("flagged")}>
              ⚑ FLAGGED
            </button>
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
        </div>
        <div className="tapefull-scroll">
          <TapeList events={shown} />
        </div>
      </section>
      <Link href="/" className="back">◂ back to command view</Link>
    </>
  );
}
