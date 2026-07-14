"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import {
  getIncidents, getRecentEvents, getStatus,
  type IncidentSummary, type Status, type TapeEvent,
} from "../lib/api";
import { compact, mmss } from "../lib/format";
import { subscribe } from "../lib/stream";
import { FleetPanel } from "./FleetPanel";
import { IncidentBoard } from "./IncidentBoard";
import { KillChain } from "./KillChain";
import { TopBar, type LinkState } from "./TopBar";
import { Throughput } from "./Throughput";

const TAPE_MAX = 200;

function Kpi({ label, value, sub, tone, href, onClick }: {
  label: string; value: string; sub?: React.ReactNode; tone?: string; href?: string; onClick?: () => void;
}) {
  const body = (
    <>
      <div className="l">{label}</div>
      <div className="n mono">{value}</div>
      {sub && <div className="s mono">{sub}</div>}
    </>
  );
  const cls = `kpi${tone ? ` ${tone}` : ""}`;
  if (href) return <Link href={href} className={`${cls} drill`}>{body}</Link>;
  if (onClick) return <button type="button" className={`${cls} drill`} onClick={onClick}>{body}</button>;
  return <div className={cls}>{body}</div>;
}

function KpiStrip({ status, apiUp, onFocusBoard }: {
  status: Status | null; apiUp: boolean; onFocusBoard: (f: "all" | "high") => void;
}) {
  const fleet = status?.fleet ?? null;
  const online = fleet ? fleet.hosts.filter((h) => h.last_seen_s !== null && h.last_seen_s < 15).length : 0;
  const warmup = status?.mode === "warmup";
  const pct = warmup && status ? Math.min(1, 1 - status.warmup_remaining_s / Math.max(status.warmup_seconds, 1)) : 0;

  return (
    <section className="kpis">
      <Kpi
        label="Mode"
        value={!apiUp ? "OFFLINE" : warmup ? "WARMUP" : "MONITOR"}
        tone={!apiUp ? "bad" : warmup ? "warm" : "good"}
        sub={!apiUp ? "api unreachable" : warmup
          ? (status!.events_seen === 0
            ? "awaiting first events"
            : <span>freeze in {mmss(status!.warmup_remaining_s)}<span className="warmbar"><i style={{ width: `${pct * 100}%` }} /></span></span>)
          : status?.baseline_ready ? "baseline frozen" : "guardrails only"}
      />
      <Kpi label="Events / min" value={String(fleet?.rate_epm ?? 0)} sub={`${compact(status?.events_seen ?? 0)} total`}
        href="/telemetry" />
      <Kpi label="Sensors" value={fleet ? `${online}/${fleet.hosts.length}` : "0/0"} sub="reporting < 15s" />
      <Kpi label="Flagged" value={String(status?.flagged_recent ?? 0)} sub="in correlation window"
        tone={(status?.flagged_recent ?? 0) > 0 ? "warm" : undefined} href="/telemetry?view=flagged" />
      <Kpi label="Incidents" value={String(status?.incident_count ?? 0)} sub="live correlated"
        onClick={() => onFocusBoard("all")} />
      <Kpi label="High conf" value={String(status?.high_confidence_count ?? 0)} sub="multi-source · multi-phase"
        tone={(status?.high_confidence_count ?? 0) > 0 ? "bad" : undefined}
        onClick={() => onFocusBoard("high")} />
    </section>
  );
}

export function CommandDeck({
  initialIncidents, initialStatus, initialTape,
}: {
  initialIncidents: IncidentSummary[];
  initialStatus: Status | null;
  initialTape: TapeEvent[];
}) {
  const [status, setStatus] = useState<Status | null>(initialStatus);
  const [incidents, setIncidents] = useState<IncidentSummary[]>(initialIncidents);
  const [tape, setTape] = useState<TapeEvent[]>([...initialTape].reverse());
  const [attributed, setAttributed] = useState<Set<string>>(new Set());
  const [apiUp, setApiUp] = useState<boolean>(initialStatus !== null);
  const [sseUp, setSseUp] = useState<boolean | null>(null);
  const [now, setNow] = useState<number | null>(null);
  const [boardFilter, setBoardFilter] = useState<"all" | "high">("all");
  const [boardFlash, setBoardFlash] = useState(false);
  const apiUpRef = useRef(apiUp);
  apiUpRef.current = apiUp;
  const sseUpRef = useRef(sseUp);
  sseUpRef.current = sseUp;
  const flashTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const focusBoard = (filter: "all" | "high") => {
    setBoardFilter(filter);
    document.getElementById("incidents")?.scrollIntoView({ behavior: "smooth", block: "start" });
    setBoardFlash(false); // restart the flash animation even on repeat clicks
    requestAnimationFrame(() => setBoardFlash(true));
    if (flashTimer.current) clearTimeout(flashTimer.current);
    flashTimer.current = setTimeout(() => setBoardFlash(false), 1600);
  };

  useEffect(() => {
    const unsub = subscribe((e) => {
      if (e.type === "telemetry") {
        setTape((prev) => [...e.events.slice().reverse(), ...prev].slice(0, TAPE_MAX));
      } else if (e.type === "incident") {
        const { type: _t, ...inc } = e;
        setIncidents((prev) => {
          const next = prev.filter((p) => p.id !== inc.id).concat(inc as IncidentSummary);
          next.sort((a, b) => b.compound_score - a.compound_score);
          return next;
        });
      } else if (e.type === "attribution") {
        setAttributed((prev) => new Set(prev).add(e.id));
      }
    }, setSseUp);

    const pollStatus = () => getStatus().then((s) => { setStatus(s); setApiUp(true); }).catch(() => setApiUp(false));
    const pollIncidents = () => {
      if (!apiUpRef.current) return;
      getIncidents().then(setIncidents).catch(() => {});
      if (sseUpRef.current !== true) {
        // stream down or never opened — keep the tape moving on polls alone
        getRecentEvents().then((t) => setTape([...t].reverse())).catch(() => {});
      }
    };
    pollStatus();
    if (initialTape.length === 0) getRecentEvents().then((t) => setTape([...t].reverse())).catch(() => {});
    const t1 = setInterval(pollStatus, 2000);
    const t2 = setInterval(pollIncidents, 5000);
    const t3 = setInterval(() => setNow(Date.now()), 1000);
    // if the SSE handshake never resolves, stop showing LINKING… and fall back to polls
    const t4 = setTimeout(() => setSseUp((v) => (v === null ? false : v)), 6000);
    setNow(Date.now());
    return () => { unsub(); clearInterval(t1); clearInterval(t2); clearInterval(t3); clearTimeout(t4); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const link: LinkState = !apiUp ? "down" : sseUp === false ? "degraded" : sseUp ? "live" : "unknown";

  return (
    <>
      <TopBar mode={apiUp ? status?.mode ?? null : null} link={link} />
      {!apiUp && (
        <div className="linkdown mono">
          ▲ backend unreachable — <span className="cmd">cd apps/api &amp;&amp; uv run uvicorn prahari.main:app --port 8000</span> · retrying…
        </div>
      )}
      <KpiStrip status={status} apiUp={apiUp} onFocusBoard={focusBoard} />
      <Throughput
        series={status?.fleet?.series ?? []}
        hasSensors={(status?.fleet?.hosts?.length ?? 0) > 0}
      />
      <KillChain events={tape} />
      <div className="cols">
        <IncidentBoard
          incidents={incidents} variant="live" attributed={attributed} now={now}
          filter={boardFilter} onClearFilter={() => setBoardFilter("all")} flash={boardFlash}
        />
        <div className="side">
          <FleetPanel hosts={status?.fleet?.hosts ?? []} tape={tape} />
        </div>
      </div>
    </>
  );
}
