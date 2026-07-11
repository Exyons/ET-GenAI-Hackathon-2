"use client";

import { useEffect, useRef, useState } from "react";

import {
  getIncidents, getRecentEvents, getStatus,
  type IncidentSummary, type Metrics, type Status, type TapeEvent,
} from "../lib/api";
import { compact, mmss } from "../lib/format";
import { subscribe } from "../lib/stream";
import { FleetPanel } from "./FleetPanel";
import { IncidentBoard } from "./IncidentBoard";
import { KillChain } from "./KillChain";
import { Tape } from "./Tape";
import { TopBar, type LinkState } from "./TopBar";
import { Throughput } from "./Throughput";

const TAPE_MAX = 80;

function Kpi({ label, value, sub, tone }: { label: string; value: string; sub?: React.ReactNode; tone?: string }) {
  return (
    <div className={`kpi${tone ? ` ${tone}` : ""}`}>
      <div className="l">{label}</div>
      <div className="n mono">{value}</div>
      {sub && <div className="s mono">{sub}</div>}
    </div>
  );
}

function KpiStrip({ status, apiUp }: { status: Status | null; apiUp: boolean }) {
  const fleet = status?.fleet;
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
          ? <span>freeze in {mmss(status!.warmup_remaining_s)}<span className="warmbar"><i style={{ width: `${pct * 100}%` }} /></span></span>
          : status?.baseline_ready ? "baseline frozen" : "guardrails only"}
      />
      <Kpi label="Events / min" value={String(fleet?.rate_epm ?? 0)} sub={`${compact(status?.events_seen ?? 0)} total`} />
      <Kpi label="Sensors" value={fleet ? `${online}/${fleet.hosts.length}` : "0/0"} sub="reporting < 15s" />
      <Kpi label="Flagged" value={String(status?.flagged_recent ?? 0)} sub="in correlation window"
        tone={(status?.flagged_recent ?? 0) > 0 ? "warm" : undefined} />
      <Kpi label="Incidents" value={String(status?.incident_count ?? 0)} sub="live correlated" />
      <Kpi label="High conf" value={String(status?.high_confidence_count ?? 0)} sub="multi-source · multi-phase"
        tone={(status?.high_confidence_count ?? 0) > 0 ? "bad" : undefined} />
    </section>
  );
}

function Benchmark({ m }: { m: Metrics | null }) {
  if (!m) return null;
  return (
    <section className="bench">
      <span className="eyebrow">Recorded LANL red-team benchmark</span>
      <span className="mono"><b className="good">{m.behavioural_recall.toFixed(2)}</b> behavioural recall</span>
      <span className="mono"><b className="bad">{m.signature_recall.toFixed(2)}</b> signature recall</span>
      <span className="mono"><b className="amp">{m.mttd_seconds}s</b> MTTD</span>
      <span className="mono"><b className="amp">{(m.false_positive_rate * 100).toFixed(1)}%</b> FP rate</span>
      <span className="mono"><b className="amp">{m.attack_techniques}</b> ATT&amp;CK techniques · air-gapped RAG</span>
    </section>
  );
}

export function CommandDeck({
  initialIncidents, initialStatus, initialTape, metrics,
}: {
  initialIncidents: IncidentSummary[];
  initialStatus: Status | null;
  initialTape: TapeEvent[];
  metrics: Metrics | null;
}) {
  const [status, setStatus] = useState<Status | null>(initialStatus);
  const [incidents, setIncidents] = useState<IncidentSummary[]>(initialIncidents);
  const [tape, setTape] = useState<TapeEvent[]>([...initialTape].reverse());
  const [attributed, setAttributed] = useState<Set<string>>(new Set());
  const [apiUp, setApiUp] = useState<boolean>(initialStatus !== null);
  const [sseUp, setSseUp] = useState<boolean | null>(null);
  const [now, setNow] = useState<number | null>(null);
  const apiUpRef = useRef(apiUp);
  apiUpRef.current = apiUp;

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
    };
    pollStatus();
    if (initialTape.length === 0) getRecentEvents().then((t) => setTape([...t].reverse())).catch(() => {});
    const t1 = setInterval(pollStatus, 2000);
    const t2 = setInterval(pollIncidents, 5000);
    const t3 = setInterval(() => setNow(Date.now()), 1000);
    setNow(Date.now());
    return () => { unsub(); clearInterval(t1); clearInterval(t2); clearInterval(t3); };
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
      <KpiStrip status={status} apiUp={apiUp} />
      <Throughput series={status?.fleet.series ?? []} />
      <KillChain events={tape} />
      <div className="cols">
        <IncidentBoard
          incidents={incidents}
          liveCount={status ? status.incident_count : null}
          attributed={attributed}
          now={now}
        />
        <div className="side">
          <FleetPanel hosts={status?.fleet.hosts ?? []} />
          <Tape events={tape} ratePerMin={status?.fleet.rate_epm ?? 0} />
        </div>
      </div>
      <Benchmark m={metrics} />
    </>
  );
}
