"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import {
  getIncidents, getRecentEvents, getStatus,
  type IncidentSummary, type Status, type TapeEvent, type ThroughputBucket,
} from "../lib/api";
import { compact, mmss } from "../lib/format";
import { subscribe } from "../lib/stream";
import { Icon } from "./Icon";
import { ThemeToggle } from "./ThemeToggle";

const TAPE_MAX = 200;

const PHASE_COLOR: Record<string, string> = {
  lateral_movement: "var(--s-auth)", discovery: "var(--s-proc)",
  execution: "var(--alert)", command_and_control: "var(--s-net)",
};
const KC_PHASES = [
  { key: "lateral_movement", label: "Lateral movement" },
  { key: "discovery", label: "Discovery" },
  { key: "execution", label: "Execution" },
  { key: "command_and_control", label: "Command & control" },
];
const TYPE_SWATCH: Record<string, string> = {
  auth: "var(--s-auth)", process: "var(--s-proc)", network_flow: "var(--s-net)",
};
const OS_TAG: Record<string, string> = { linux: "LNX", windows: "WIN", unknown: "—" };
const OS_COLOR: Record<string, string> = { LNX: "var(--s-auth)", WIN: "var(--violet)", "—": "var(--haze)" };
const PIPELINE = [
  { slug: "ingest", name: "Baseline" }, { slug: "detect", name: "Sentinel" },
  { slug: "correlate", name: "Correlator" }, { slug: "attribute", name: "Attribution" },
  { slug: "respond", name: "Responder" },
];

function clock(iso: string): string { return new Date(iso).toISOString().slice(11, 19); }
function hostState(s: number | null): "online" | "stale" | "offline" {
  if (s === null) return "offline";
  if (s < 15) return "online";
  if (s < 60) return "stale";
  return "offline";
}
function seenLabel(s: number | null): string {
  if (s === null) return "never";
  if (s < 1) return "now";
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  return `${Math.floor(s / 3600)}h`;
}
function ago(iso: string, now: number | null): string {
  if (!now) return "";
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function Sparkline({ series }: { series: ThroughputBucket[] }) {
  const buckets = series.slice(-22);
  const vals = buckets.map((b) => b.auth + b.process + b.network_flow);
  const max = Math.max(1, ...vals);
  const dominant = (b: ThroughputBucket) =>
    b.network_flow >= b.auth && b.network_flow >= b.process ? "var(--s-net)"
      : b.process >= b.auth ? "var(--s-proc)" : "var(--s-auth)";
  return (
    <svg viewBox="0 0 204 40" className="cw-spark" role="img" aria-label="Ingest throughput">
      {buckets.map((b, i) => {
        const h = Math.max(2, ((b.auth + b.process + b.network_flow) / max) * 38);
        return <rect key={i} x={4 + i * 9} y={40 - h} width={6} height={h} rx={1} fill={dominant(b)} />;
      })}
    </svg>
  );
}

export function CommandWall({
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
  const [utc, setUtc] = useState("--:--:--");
  const apiUpRef = useRef(apiUp); apiUpRef.current = apiUp;
  const sseUpRef = useRef(sseUp); sseUpRef.current = sseUp;

  useEffect(() => {
    const unsub = subscribe((e) => {
      if (e.type === "telemetry") setTape((p) => [...e.events.slice().reverse(), ...p].slice(0, TAPE_MAX));
      else if (e.type === "incident") {
        const { type: _t, ...inc } = e;
        setIncidents((p) => {
          const next = p.filter((x) => x.id !== inc.id).concat(inc as IncidentSummary);
          next.sort((a, b) => b.compound_score - a.compound_score);
          return next;
        });
      } else if (e.type === "attribution") setAttributed((p) => new Set(p).add(e.id));
    }, setSseUp);

    const pollStatus = () => getStatus().then((s) => { setStatus(s); setApiUp(true); }).catch(() => setApiUp(false));
    const pollIncidents = () => {
      if (!apiUpRef.current) return;
      getIncidents().then(setIncidents).catch(() => {});
      if (sseUpRef.current !== true) getRecentEvents().then((t) => setTape([...t].reverse())).catch(() => {});
    };
    pollStatus();
    if (initialTape.length === 0) getRecentEvents().then((t) => setTape([...t].reverse())).catch(() => {});
    const t1 = setInterval(pollStatus, 2000);
    const t2 = setInterval(pollIncidents, 5000);
    const t3 = setInterval(() => { setNow(Date.now()); setUtc(new Date().toISOString().slice(11, 19)); }, 1000);
    const t4 = setTimeout(() => setSseUp((v) => (v === null ? false : v)), 6000);
    setNow(Date.now()); setUtc(new Date().toISOString().slice(11, 19));
    return () => { unsub(); clearInterval(t1); clearInterval(t2); clearInterval(t3); clearTimeout(t4); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---- derive view data ----
  const fleet = status?.fleet ?? null;
  const hosts = fleet?.hosts ?? [];
  const online = hosts.filter((h) => hostState(h.last_seen_s) === "online").length;
  const warmup = status?.mode === "warmup";
  const mode = !apiUp ? { label: "OFFLINE", color: "var(--alert)", tone: "off" }
    : warmup ? { label: "WARMUP", color: "var(--phosphor)", tone: "warm" }
      : { label: "MONITOR", color: "var(--calm)", tone: "ok" };
  const modeSub = !apiUp ? "api unreachable · retrying…"
    : warmup ? (status!.events_seen === 0 ? "awaiting first events" : `freeze in ${mmss(status!.warmup_remaining_s)} · learning baseline`)
      : status?.baseline_ready ? "baseline frozen · guardrails live" : "guardrails only";

  const flagged = tape.filter((e) => e.flagged);
  const kcCounts = new Map<string, number>();
  for (const e of flagged) kcCounts.set(e.phase, (kcCounts.get(e.phase) ?? 0) + 1);
  const kcMax = Math.max(1, ...KC_PHASES.map((p) => kcCounts.get(p.key) ?? 0));

  const series = fleet?.series ?? [];
  const peak = Math.max(0, ...series.map((b) => b.auth + b.process + b.network_flow));

  const link = !apiUp ? { label: "LINK DOWN", color: "var(--alert)" }
    : sseUp === false ? { label: "● POLLING", color: "var(--phosphor)" }
      : sseUp ? { label: "● LIVE · SSE", color: "var(--calm)" }
        : { label: "LINKING…", color: "var(--haze)" };

  const pipe = status?.pipeline;
  const resp = status?.response;
  const pipeState = (slug: string): { text: string; color: string; alert?: boolean; warn?: boolean } => {
    switch (slug) {
      case "ingest": return status?.baseline_ready ? { text: "frozen", color: "var(--calm)" }
        : warmup ? { text: "warming", color: "var(--phosphor)", warn: true } : { text: "guardrails", color: "var(--haze)" };
      case "detect": return { text: `${fleet?.rate_epm ?? 0}/min`, color: "var(--haze)" };
      case "correlate": { const n = status?.incident_count ?? 0; return { text: `${n} open`, color: n > 0 ? "var(--phosphor)" : "var(--haze)", warn: n > 0 }; }
      case "attribute": return pipe?.attribution_error ? { text: "error", color: "var(--alert)", alert: true } : { text: "mapping", color: "var(--haze)" };
      case "respond": { const n = resp?.pending ?? 0; return { text: n > 0 ? `${n} awaiting` : "idle", color: n > 0 ? "var(--alert)" : "var(--haze)", alert: n > 0 }; }
      default: return { text: "", color: "var(--haze)" };
    }
  };

  return (
    <div className="cw">
      {/* top bar */}
      <div className="cw-bar">
        <Link href="/" className="cw-brand"><span className="deva">प्रहरी</span><span className="name">PRAHARI</span></Link>
        <span className="cw-sep" />
        <span className="cw-nav on">Command</span>
        <Link href="/telemetry" className="cw-nav">Telemetry</Link>
        <Link href="/report" className="cw-nav">Report</Link>
        <Link href="/settings" className="cw-nav">Settings</Link>
        <span className="spacer" />
        {(status?.high_confidence_count ?? 0) > 0 && (
          <span className="cw-chip hi mono">● {status!.high_confidence_count} HIGH-CONF</span>
        )}
        <span className="cw-chip mono" style={{ color: link.color, borderColor: "currentcolor" }}>{link.label}</span>
        <ThemeToggle compact />
        <span className="cw-chip clock mono">{utc} UTC</span>
      </div>

      <div className="cw-wall">
        {/* ===== PULSE ===== */}
        <div className="cw-pulse">
          <div className={`cw-modetile ${mode.tone}`}>
            <div className="cw-k mono">MODE</div>
            <div className="cw-modeval mono" style={{ color: mode.color }}>{mode.label}</div>
            <div className="cw-modesub mono">{modeSub}</div>
          </div>

          <div>
            <div className="cw-k mono">SENSORS ONLINE</div>
            <div className="cw-online"><span className="n mono">{online}</span><span className="d mono">/ {hosts.length}</span></div>
            <div className="cw-sbars">
              {(hosts.length ? hosts : [null, null, null]).map((h, i) => {
                const st = h ? hostState(h.last_seen_s) : "offline";
                const c = st === "online" ? "var(--calm)" : st === "stale" ? "var(--phosphor)" : "var(--line)";
                return <span key={i} className="cw-sbar" style={{ background: c }} />;
              })}
            </div>
          </div>

          <div>
            <div className="cw-k mono">KILL CHAIN · FLAGGED</div>
            <div className="cw-kc">
              {KC_PHASES.map((p) => {
                const n = kcCounts.get(p.key) ?? 0;
                return (
                  <div className="cw-kcrow" key={p.key}>
                    <span className="cw-kcn mono" style={{ color: PHASE_COLOR[p.key] }}>{n}</span>
                    <div className="cw-kcbody">
                      <div className="cw-kclabel">{p.label}</div>
                      <div className="cw-kctrack"><span style={{ width: `${(n / kcMax) * 100}%`, background: PHASE_COLOR[p.key] }} /></div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <Link href="/telemetry" className="cw-ingest">
            <div className="cw-ingest-head"><span className="cw-k mono">INGEST</span>
              <span className="cw-epm mono">{fleet?.rate_epm ?? 0}<span className="u">/min</span></span></div>
            <Sparkline series={series} />
            <div className="cw-ingest-foot mono">-6m ————— now · peak {peak}/10s · {compact(status?.events_seen ?? 0)} total</div>
          </Link>
        </div>

        {/* ===== INCIDENTS + PIPELINE ===== */}
        <div className="cw-center">
          <div className="cw-sec-head">
            <span className="cw-sec-t">ACTIVE INCIDENTS</span>
            <span className="cw-sec-s mono">ranked by compound risk</span>
            <span className="spacer" />
            <span className="cw-chip live mono">LIVE CORRELATION</span>
          </div>
          {incidents.length === 0 ? (
            <div className="cw-empty mono">No live incidents — correlation quiet, monitoring telemetry.</div>
          ) : (
            <div className="cw-inclist">
              {incidents.map((i) => {
                const hi = i.high_confidence;
                const sev = hi ? "var(--alert)" : "var(--line)";
                const scoreColor = i.compound_score > 0.4 ? "var(--phosphor)" : i.compound_score > 0.25 ? "var(--paper)" : "var(--haze)";
                return (
                  <Link key={i.id} href={`/incidents/${i.id}`} className="cw-inc" style={{ borderLeftColor: sev }}>
                    <div className={`cw-inc-entity${hi ? " hi" : ""}`}>
                      <span className="cw-inc-lbl mono">ENTITY</span>
                      <span className="cw-inc-name">{i.entity}</span>
                    </div>
                    <div className="cw-inc-mid">
                      <div className="cw-inc-pills">
                        <span className={`cw-pill mono ${hi ? "hi" : i.compound_score > 0.3 ? "watch" : "low"}`}>
                          {hi ? "● HIGH-CONFIDENCE" : "WATCH"}
                        </span>
                        {i.is_true_positive && <span className="cw-pill mono rt">RED-TEAM CONFIRMED</span>}
                        {attributed.has(i.id) && <span className="cw-pill mono attr">ATT&amp;CK MAPPED</span>}
                      </div>
                      <div className="cw-inc-chain mono">
                        {i.phases.map((ph, idx) => (
                          <span key={ph}>
                            {idx > 0 && <span className="cw-arrow"> ▸ </span>}
                            <span style={{ color: PHASE_COLOR[ph] ?? "var(--haze)" }}>{ph.replace(/_/g, " ")}</span>
                          </span>
                        ))}
                      </div>
                      <div className="cw-inc-meta mono">
                        <b>{i.event_count}</b> events · <b>{i.source_count}</b> {i.source_count === 1 ? "sensor" : "sensors"}
                        {" "}<span className="dim">[{i.sources.join(" · ")}]</span> · first seen <b>{clock(i.start)}</b> · {ago(i.start, now)}
                      </div>
                      <div className="cw-inc-meter"><span style={{ width: `${Math.round(i.compound_score * 100)}%`, background: hi ? "linear-gradient(90deg,var(--phosphor),var(--alert))" : "var(--phosphor)" }} /></div>
                    </div>
                    <div className="cw-inc-score">
                      <div className="v mono" style={{ color: scoreColor }}>{i.compound_score.toFixed(2)}</div>
                      <div className="c mono">COMPOUND</div>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}

          <div className="cw-pipe">
            <div className="cw-pipe-head">
              <span className="cw-k mono">PIPELINE</span>
              <span className="cw-pipe-flow mono">collect → screen → detect → correlate → attribute → respond</span>
            </div>
            <div className="cw-pipe-cards">
              {PIPELINE.map((p) => {
                const s = pipeState(p.slug);
                return (
                  <Link key={p.slug} href={`/pipeline/${p.slug}`} className={`cw-pcard${s.alert ? " alert" : s.warn ? " warn" : ""}`}>
                    <div className="cw-pcard-top"><span className="cw-pdot" style={{ background: s.color }} /><span className="cw-pname">{p.name}</span></div>
                    <div className="cw-pstate mono" style={{ color: s.color }}>{s.text}</div>
                  </Link>
                );
              })}
            </div>
          </div>
        </div>

        {/* ===== FLEET + TAPE ===== */}
        <div className="cw-right">
          <div className="cw-fleet">
            <div className="cw-rhead"><span className="cw-rtitle">SENSOR FLEET</span><span className="cw-rmeta mono ok">{online}/{hosts.length}</span></div>
            {hosts.length === 0 ? (
              <div className="cw-empty mono sm">no machines reporting</div>
            ) : hosts.map((h) => {
              const st = hostState(h.last_seen_s);
              const c = st === "online" ? "var(--calm)" : st === "stale" ? "var(--phosphor)" : "var(--line)";
              const os = OS_TAG[h.os] ?? "—";
              return (
                <div className="cw-hrow" key={h.host}>
                  <span className="cw-hdot" style={{ background: c }} />
                  <span className="cw-hname mono" style={{ color: st === "offline" ? "var(--haze)" : "var(--paper)" }}>
                    {h.host} <span className="cw-hos" style={{ color: OS_COLOR[os] }}>{os}</span>
                  </span>
                  <span className="cw-hepm mono">{h.epm}/min</span>
                  <span className="cw-hseen mono" style={{ color: st === "online" ? "var(--calm)" : st === "stale" ? "var(--phosphor)" : "var(--haze)" }}>{seenLabel(h.last_seen_s)}</span>
                </div>
              );
            })}
          </div>
          <div className="cw-tape">
            <div className="cw-rhead"><span className="cw-rtitle">LIVE TAPE</span>
              <span className="cw-rmeta mono ok"><span className="cw-pulsedot">●</span> streaming</span></div>
            {tape.slice(0, 12).map((e, i) => (
              <div className="cw-trow" key={`${e.timestamp}-${i}`}>
                <span className="cw-tt mono">{clock(e.timestamp)}</span>
                <i className="cw-tsw" style={{ background: TYPE_SWATCH[e.event_type] ?? "var(--haze)" }} />
                <span className="cw-twhat mono" style={{ color: e.flagged ? "var(--paper)" : "var(--haze)" }}>
                  {e.host} · {e.detail || e.event_type}
                </span>
                {e.flagged && <span className="cw-tflag mono"><Icon name="flag" /></span>}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
