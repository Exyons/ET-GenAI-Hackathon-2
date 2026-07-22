"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  addToBlocklist, getIncident, getIncidents, getNetworkDetail, getRecentEvents, getStatus,
  type IncidentDetail, type IncidentSummary, type NetworkDetail, type Status, type ThroughputBucket,
} from "../lib/api";
import { compact, mmss } from "../lib/format";
import { subscribe } from "../lib/stream";
import { Icon } from "./Icon";
import { ThemeToggle } from "./ThemeToggle";

const TAPE_MAX = 200;
const PHASE_COLOR: Record<string, string> = {
  lateral_movement: "var(--s-auth)", discovery: "var(--s-proc)",
  execution: "var(--alert)", command_and_control: "var(--s-net)", exfiltration: "var(--alert)",
};
const KC_PHASES = [
  { key: "lateral_movement", label: "Lateral", color: "var(--s-auth)" },
  { key: "discovery", label: "Discovery", color: "var(--s-proc)" },
  { key: "execution", label: "Execution", color: "var(--alert)" },
  { key: "command_and_control", label: "C2", color: "var(--s-net)" },
];

// external/public IPv4 only — C2 destinations are never on the internal ranges
function isPublicIp(ip: string): boolean {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 192 && b === 168) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  return true;
}

function clock(iso: string): string { return new Date(iso).toISOString().slice(11, 19); }
function hm(iso: string): string { return new Date(iso).toISOString().slice(11, 16); }
function fmtBytes(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} MB`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)} KB`;
  return `${n} B`;
}

// ---- graph model ------------------------------------------------------------
type MapNode = {
  id: string; kind: "focus" | "host" | "ip" | "predicted";
  label: string; sub: string; subColor: string; stroke: string;
  x: number; y: number; appt: number;
};
type MapEdge = { x1: number; y1: number; x2: number; y2: number; color: string; dashed: boolean; appt: number };

// viewBox is 0 0 760 380; focus centred, predicted directly above it.
// hosts are ovals (ellipses); the constants below are the semi-axes / pill dims.
const FOCUS = { x: 340, y: 220 };
const FOCUS_RX = 36, FOCUS_RY = 24, HOST_RX = 30, HOST_RY = 20, R_PRED = 23, IP_W = 92, IP_H = 24;
// edge endpoints reference the horizontal reach of each shape
const R_FOCUS = FOCUS_RX, R_HOST = HOST_RX;
const TACTIC_ABBR: Record<string, string> = {
  exfiltration: "EXFIL", discovery: "DISCVR", lateral_movement: "LATERAL", command_and_control: "C2",
  execution: "EXEC", collection: "COLLECT", persistence: "PERSIST", privilege_escalation: "PRIVESC",
  credential_access: "CREDS", defense_evasion: "EVASION", impact: "IMPACT", reconnaissance: "RECON",
  initial_access: "ACCESS",
};
function abbr(t: string): string { return TACTIC_ABBR[t] ?? t.replace(/[-_]/g, " ").slice(0, 7).toUpperCase(); }
function spread(i: number, n: number, top: number, bot: number): number {
  return n <= 1 ? (top + bot) / 2 : top + (i / (n - 1)) * (bot - top);
}

function buildGraph(incidents: IncidentSummary[], focusDetail: IncidentDetail | null) {
  const nodes: MapNode[] = [];
  const edges: MapEdge[] = [];
  if (incidents.length === 0) return { nodes, edges, predicted: "" };

  const focus = incidents[0];
  nodes.push({ id: focus.id, kind: "focus", label: focus.entity, sub: focus.compound_score.toFixed(2),
    subColor: "var(--phosphor)", stroke: "var(--alert)", x: FOCUS.x, y: FOCUS.y, appt: 0 });

  // C2 external IPs from the focus incident's network flows (public only)
  const ipTimes = new Map<string, number>();
  for (const e of focusDetail?.timeline ?? []) {
    if (e.dst_ip && isPublicIp(e.dst_ip)) ipTimes.set(e.dst_ip, Math.min(ipTimes.get(e.dst_ip) ?? Infinity, new Date(e.timestamp).getTime()));
  }
  const ips = [...ipTimes.entries()].sort((a, b) => a[1] - b[1]).slice(0, 5);
  const laterals = incidents.slice(1, 5);

  const timed = [
    ...ips.map(([ip, t]) => ({ key: ip, t })),
    ...laterals.map((i) => ({ key: i.id, t: new Date(i.start).getTime() })),
  ].sort((a, b) => a.t - b.t);
  const appt = new Map<string, number>();
  timed.forEach((x, i) => appt.set(x.key, timed.length <= 1 ? 45 : 16 + (i / (timed.length - 1)) * 58));

  ips.forEach(([ip], i) => {
    const y = spread(i, ips.length, 120, 350), x = 610;
    nodes.push({ id: `ip:${ip}`, kind: "ip", label: ip, sub: "C2", subColor: "var(--alert)",
      stroke: "var(--alert)", x, y, appt: appt.get(ip) ?? 40 });
    edges.push({ x1: FOCUS.x + R_FOCUS, y1: FOCUS.y, x2: x - IP_W / 2 - 4, y2: y, color: "var(--s-net)", dashed: false, appt: appt.get(ip) ?? 40 });
  });
  laterals.forEach((inc, i) => {
    const y = spread(i, laterals.length, 140, 330), x = 120;
    nodes.push({ id: inc.id, kind: "host", label: inc.entity, sub: inc.compound_score.toFixed(2),
      subColor: inc.compound_score > 0.3 ? "var(--phosphor)" : "var(--haze)",
      stroke: inc.high_confidence ? "var(--alert)" : "var(--phosphor)", x, y, appt: appt.get(inc.id) ?? 50 });
    edges.push({ x1: FOCUS.x - R_FOCUS, y1: FOCUS.y, x2: x + R_HOST + 4, y2: y, color: "var(--phosphor)", dashed: true, appt: appt.get(inc.id) ?? 50 });
  });

  const predicted = focusDetail?.attribution.predicted_next ?? "";
  if (predicted) {
    const py = 74;
    nodes.push({ id: "predicted", kind: "predicted", label: abbr(predicted), sub: "p 1.0",
      subColor: "var(--haze)", stroke: "var(--alert)", x: FOCUS.x, y: py, appt: 82 });
    edges.push({ x1: FOCUS.x, y1: FOCUS.y - FOCUS_RY, x2: FOCUS.x, y2: py + R_PRED + 2, color: "var(--alert)", dashed: true, appt: 82 });
  }
  return { nodes, edges, predicted };
}

// ---- component --------------------------------------------------------------
export function CommandMap({
  initialIncidents, initialStatus, initialTape,
}: {
  initialIncidents: IncidentSummary[]; initialStatus: Status | null;
  initialTape: import("../lib/api").TapeEvent[];
}) {
  const [status, setStatus] = useState<Status | null>(initialStatus);
  const [incidents, setIncidents] = useState<IncidentSummary[]>(initialIncidents);
  const [tape, setTape] = useState(() => [...initialTape].reverse());
  const [attributed, setAttributed] = useState<Set<string>>(new Set());
  const [apiUp, setApiUp] = useState(initialStatus !== null);
  const [sseUp, setSseUp] = useState<boolean | null>(null);
  const [utc, setUtc] = useState("--:--:--");
  const [t, setT] = useState(100);
  const [playing, setPlaying] = useState(false);
  const [sel, setSel] = useState<string | null>(null);
  const [focusDetail, setFocusDetail] = useState<IncidentDetail | null>(null);
  const [incCache, setIncCache] = useState<Record<string, IncidentDetail>>({});
  const [ipCache, setIpCache] = useState<Record<string, NetworkDetail>>({});
  const apiUpRef = useRef(apiUp); apiUpRef.current = apiUp;
  const sseUpRef = useRef(sseUp); sseUpRef.current = sseUp;

  useEffect(() => {
    const unsub = subscribe((e) => {
      if (e.type === "telemetry") setTape((p) => [...e.events.slice().reverse(), ...p].slice(0, TAPE_MAX));
      else if (e.type === "incident") {
        const { type: _t, ...inc } = e;
        setIncidents((p) => { const n = p.filter((x) => x.id !== inc.id).concat(inc as IncidentSummary); n.sort((a, b) => b.compound_score - a.compound_score); return n; });
      } else if (e.type === "attribution") setAttributed((p) => new Set(p).add(e.id));
    }, setSseUp);
    const pollStatus = () => getStatus().then((s) => { setStatus(s); setApiUp(true); }).catch(() => setApiUp(false));
    const pollInc = () => {
      if (!apiUpRef.current) return;
      getIncidents().then(setIncidents).catch(() => {});
      if (sseUpRef.current !== true) getRecentEvents().then((x) => setTape([...x].reverse())).catch(() => {});
    };
    pollStatus();
    if (initialTape.length === 0) getRecentEvents().then((x) => setTape([...x].reverse())).catch(() => {});
    const t1 = setInterval(pollStatus, 2000);
    const t2 = setInterval(pollInc, 5000);
    const t3 = setInterval(() => setUtc(new Date().toISOString().slice(11, 19)), 1000);
    const t4 = setTimeout(() => setSseUp((v) => (v === null ? false : v)), 6000);
    setUtc(new Date().toISOString().slice(11, 19));
    return () => { unsub(); clearInterval(t1); clearInterval(t2); clearInterval(t3); clearTimeout(t4); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const focus = incidents[0] ?? null;
  // fetch the focus incident detail (evidence + C2 edges + predicted)
  useEffect(() => {
    if (!focus) { setFocusDetail(null); return; }
    getIncident(focus.id).then(setFocusDetail).catch(() => {});
  }, [focus?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const { nodes, edges } = useMemo(() => buildGraph(incidents, focusDetail),
    [incidents, focusDetail]);

  // play/pause the replay: advance t, loop back to 0 when it reaches the end
  useEffect(() => {
    if (!playing) return;
    const h = setInterval(() => setT((v) => (v >= 100 ? 0 : Math.min(100, v + 2))), 90);
    return () => clearInterval(h);
  }, [playing]);

  // default selection = focus
  useEffect(() => {
    if (nodes.length === 0) { setSel(null); return; }
    if (!sel || !nodes.some((n) => n.id === sel)) setSel(nodes[0].id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes.map((n) => n.id).join(",")]);

  // lazily fetch detail for the selected node
  const fetchSel = useCallback((id: string) => {
    if (id.startsWith("ip:")) {
      const ip = id.slice(3);
      if (!ipCache[ip]) getNetworkDetail(ip).then((d) => setIpCache((c) => ({ ...c, [ip]: d }))).catch(() => {});
    } else if (id !== "predicted" && id !== focus?.id) {
      if (!incCache[id]) getIncident(id).then((d) => setIncCache((c) => ({ ...c, [id]: d }))).catch(() => {});
    }
  }, [ipCache, incCache, focus?.id]);
  useEffect(() => { if (sel) fetchSel(sel); }, [sel, fetchSel]);

  const isPred = t >= 80;
  const link = !apiUp ? { label: "LINK DOWN", color: "var(--alert)" }
    : sseUp === false ? { label: "● POLLING", color: "var(--phosphor)" }
      : sseUp ? { label: "● LIVE · SSE", color: "var(--calm)" } : { label: "LINKING…", color: "var(--haze)" };

  const fleet = status?.fleet ?? null;
  const hosts = fleet?.hosts ?? [];
  const online = hosts.filter((h) => (h.last_seen_s ?? 1e9) < 15).length;
  const warmup = status?.mode === "warmup";
  const mode = !apiUp ? { label: "OFFLINE", color: "var(--alert)", tint: "rgba(229,72,77,0.06)", sub: "api unreachable" }
    : warmup ? { label: "WARMUP", color: "var(--phosphor)", tint: "rgba(245,166,35,0.05)", sub: status && status.events_seen > 0 ? `freeze in ${mmss(status.warmup_remaining_s)}` : "learning baseline" }
      : { label: "MONITOR", color: "var(--calm)", tint: "rgba(63,182,168,0.05)", sub: status?.baseline_ready ? "baseline frozen" : "guardrails only" };

  const flaggedTape = tape.filter((e) => e.flagged);
  const kcCount = (k: string) => flaggedTape.filter((e) => e.phase === k).length;

  return (
    <div className="cm">
      {/* top bar */}
      <div className="cm-bar">
        <Link href="/" className="cm-brand"><span className="deva">प्रहरी</span><span className="name">PRAHARI</span></Link>
        <span className="cm-sep" />
        <span className="cm-nav on">Command</span>
        <Link href="/telemetry" className="cm-nav">Telemetry</Link>
        <Link href="/report" className="cm-nav">Report</Link>
        <Link href="/settings" className="cm-nav">Settings</Link>
        <span className="spacer" />
        {(status?.high_confidence_count ?? 0) > 0 && <span className="cm-chip hi mono">● {status!.high_confidence_count} HIGH-CONF</span>}
        <span className="cm-chip mono" style={{ color: link.color, borderColor: "currentcolor" }}>{link.label}</span>
        <ThemeToggle compact />
        <span className="cm-chip clock mono">{utc} UTC</span>
      </div>

      {/* status ribbon */}
      <div className="cm-ribbon">
        <div className="cm-cell" style={{ background: mode.tint }}>
          <div className="k mono">MODE</div><div className="v mono" style={{ color: mode.color }}>{mode.label}</div><div className="s mono">{mode.sub}</div>
        </div>
        <Link href="/telemetry" className="cm-cell">
          <div className="k mono">EVENTS / MIN</div><div className="v mono">{fleet?.rate_epm ?? 0}</div><div className="s mono">{compact(status?.events_seen ?? 0)} total</div>
        </Link>
        <div className="cm-cell"><div className="k mono">SENSORS</div><div className="v mono">{online}/{hosts.length}</div><div className="s mono">reporting &lt; 15s</div></div>
        <Link href="/telemetry?view=flagged" className="cm-cell"><div className="k mono">FLAGGED</div><div className="v mono" style={{ color: (status?.flagged_recent ?? 0) > 0 ? "var(--phosphor)" : undefined }}>{status?.flagged_recent ?? 0}</div><div className="s mono">in window</div></Link>
        <Link href="/telemetry?view=incidents" className="cm-cell"><div className="k mono">INCIDENTS</div><div className="v mono">{status?.incident_count ?? 0}</div><div className="s mono">live correlated</div></Link>
        <Link href="/telemetry?view=high" className="cm-cell hi"><div className="k mono">HIGH CONF</div><div className="v mono" style={{ color: "var(--alert)" }}>{status?.high_confidence_count ?? 0}</div><div className="s mono">multi-source</div></Link>
      </div>

      {/* body */}
      <div className="cm-body">
        <div className="cm-main">
          <div className="cm-sec">
            <span className="cm-sec-t">ATTACK MAP</span>
            <span className="cm-sec-s mono">{focus ? <>focus <b>{focus.entity}</b> · click a node · scroll to zoom</> : "no active incidents — monitoring"}</span>
          </div>
          <div className="cm-mapwrap">
            {nodes.length === 0
              ? <div className="cm-mapempty mono">Correlation quiet. When hosts start chaining kill-chain phases, the attack graph draws itself here.</div>
              : <AttackSvg nodes={nodes} edges={edges} t={t} sel={sel} onSelect={setSel} />}
          </div>
          {nodes.length > 0 && (
            <div className="cm-scrub">
              <div className="cm-scrub-head">
                <button type="button" className="cm-play" onClick={() => setPlaying((p) => !p)} aria-label={playing ? "pause" : "play"}>
                  {playing
                    ? <svg viewBox="0 0 24 24" width="11" height="11"><rect x="6" y="5" width="4" height="14" fill="currentColor" /><rect x="14" y="5" width="4" height="14" fill="currentColor" /></svg>
                    : <svg viewBox="0 0 24 24" width="11" height="11"><path d="M7 5v14l11-7z" fill="currentColor" /></svg>}
                </button>
                <span className="k mono">REPLAY · watch the attack build</span>
                <span className="spacer" />
                <span className="mono" style={{ color: isPred ? "var(--alert)" : "var(--calm)" }}>{isPred ? "▶ predicted" : "▶ live · now"}</span>
              </div>
              <div className="cm-track">
                <div className="cm-track-base" />
                <div className="cm-track-fill" style={{ width: `${Math.min(t, 80)}%` }} />
                <div className="cm-track-pred" />
                <div className="cm-track-predfill" style={{ width: `${isPred ? (t - 80) : 0}%` }} />
                <div className="cm-handle" style={{ left: `${t}%` }} />
                <input type="range" className="cm-range" min={0} max={100} value={t} onChange={(e) => { setPlaying(false); setT(Number(e.target.value)); }} aria-label="Replay timeline" />
              </div>
              <div className="cm-track-labels mono">
                <span>{focus ? hm(focus.start) : ""} start</span><span>C2</span><span>lateral</span>
                <span style={{ color: "var(--haze)" }}>now</span><span style={{ color: "var(--alert)" }}>→ predicted</span>
              </div>
            </div>
          )}
        </div>

        {/* right: node detail + system health */}
        <div className="cm-right">
          {sel && <NodeDetail sel={sel} focus={focus} focusDetail={focusDetail} incCache={incCache} ipCache={ipCache} attributed={attributed}
            onBlocked={(ip) => getNetworkDetail(ip).then((d) => setIpCache((c) => ({ ...c, [ip]: d }))).catch(() => {})} />}
          <div className="cm-health">
            <div className="cm-rail-head">SYSTEM HEALTH</div>
            <div>
              <div className="cm-rail-row"><span className="cm-rail-lbl">Ingest</span><span className="mono cm-rail-sub">peak {Math.max(0, ...(fleet?.series ?? []).map((b) => b.auth + b.process + b.network_flow))}/10s</span></div>
              <Sparkline series={fleet?.series ?? []} />
              <div className="cm-legend mono">
                <span><i style={{ background: "var(--s-auth)" }} />AUTH</span>
                <span><i style={{ background: "var(--s-proc)" }} />PROC</span>
                <span><i style={{ background: "var(--s-net)" }} />NET</span>
              </div>
            </div>
            <div>
              <div className="cm-rail-lbl2">Kill chain <span className="mono cm-rail-sub">· flagged</span></div>
              <div className="cm-kcgrid">
                {KC_PHASES.map((p) => (
                  <div className="cm-kccell" key={p.key} style={{ borderColor: `color-mix(in srgb, ${p.color} 25%, transparent)`, background: `color-mix(in srgb, ${p.color} 10%, transparent)` }}>
                    <div className="n mono" style={{ color: p.color }}>{kcCount(p.key)}</div><div className="l">{p.label}</div>
                  </div>
                ))}
              </div>
            </div>
            <PipelineList status={status} warmup={warmup} />
            <div className="cm-fleet">
              <div className="cm-rail-row"><span className="cm-rail-lbl">Sensor fleet</span><span className="mono cm-rail-sub ok">{online}/{hosts.length} online</span></div>
              {hosts.slice(0, 5).map((h) => {
                const st = (h.last_seen_s ?? 1e9) < 15 ? "on" : (h.last_seen_s ?? 1e9) < 60 ? "stale" : "off";
                const c = st === "on" ? "var(--calm)" : st === "stale" ? "var(--phosphor)" : "var(--line)";
                const seen = h.last_seen_s === null ? "never" : h.last_seen_s < 60 ? `${Math.round(h.last_seen_s)}s` : `${Math.floor(h.last_seen_s / 60)}m`;
                return (
                  <div className="cm-hrow" key={h.host}>
                    <span className="cm-hdot" style={{ background: c }} />
                    <span className="cm-hname mono" style={{ color: st === "off" ? "var(--haze)" : "var(--paper)" }}>{h.host} <span style={{ color: "var(--s-auth)", fontSize: 9 }}>{({ linux: "LNX", windows: "WIN", unknown: "—" })[h.os]}</span></span>
                    <span className="mono" style={{ fontSize: 10.5, color: c }}>{seen}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ---- attack SVG (pan + zoom) ------------------------------------------------
const VB_W = 760, VB_H = 380;

function AttackSvg({ nodes, edges, t, sel, onSelect }:
  { nodes: MapNode[]; edges: MapEdge[]; t: number; sel: string | null; onSelect: (id: string) => void }) {
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const wrapRef = useRef<HTMLDivElement>(null);
  const drag = useRef<{ x: number; y: number; px: number; py: number; moved: boolean } | null>(null);
  const op = (appt: number) => (t >= appt ? 1 : 0.14);
  const clampK = (k: number) => Math.min(4, Math.max(0.6, k));

  // wheel zoom around the cursor (native listener so we can preventDefault)
  useEffect(() => {
    const wrap = wrapRef.current; if (!wrap) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const r = wrap.getBoundingClientRect();
      const mx = ((e.clientX - r.left) / r.width) * VB_W, my = ((e.clientY - r.top) / r.height) * VB_H;
      setView((v) => { const nk = clampK(v.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12)); return { k: nk, x: mx - (mx - v.x) * (nk / v.k), y: my - (my - v.y) * (nk / v.k) }; });
    };
    wrap.addEventListener("wheel", onWheel, { passive: false });
    return () => wrap.removeEventListener("wheel", onWheel);
  }, []);

  const onDown = (e: React.PointerEvent) => { drag.current = { x: e.clientX, y: e.clientY, px: view.x, py: view.y, moved: false }; };
  const onMove = (e: React.PointerEvent) => {
    if (!drag.current || !wrapRef.current) return;
    const r = wrapRef.current.getBoundingClientRect();
    const dx = ((e.clientX - drag.current.x) / r.width) * VB_W, dy = ((e.clientY - drag.current.y) / r.height) * VB_H;
    if (Math.abs(e.clientX - drag.current.x) + Math.abs(e.clientY - drag.current.y) > 3) drag.current.moved = true;
    setView((v) => ({ ...v, x: drag.current!.px + dx, y: drag.current!.py + dy }));
  };
  const onUp = () => { drag.current = null; };
  const zoomBtn = (f: number) => setView((v) => { const nk = clampK(v.k * f); return { k: nk, x: VB_W / 2 - (VB_W / 2 - v.x) * (nk / v.k), y: VB_H / 2 - (VB_H / 2 - v.y) * (nk / v.k) }; });
  const reset = () => setView({ k: 1, x: 0, y: 0 });
  const pick = (id: string) => { if (!drag.current?.moved) onSelect(id); };

  return (
    <div className="cm-mapinner" ref={wrapRef}>
      <svg viewBox={`0 0 ${VB_W} ${VB_H}`} className="cm-map" role="img" aria-label="Attack graph" preserveAspectRatio="xMidYMid meet"
        onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp} onPointerLeave={onUp} style={{ cursor: "grab", touchAction: "none" }}>
        <defs>
          <marker id="cmArrN" markerWidth="5" markerHeight="5" refX="4" refY="2.5" orient="auto"><path d="M0,0 L4.2,2.5 L0,5 Z" fill="var(--s-net)" /></marker>
          <marker id="cmArrA" markerWidth="5" markerHeight="5" refX="4" refY="2.5" orient="auto"><path d="M0,0 L4.2,2.5 L0,5 Z" fill="var(--phosphor)" /></marker>
          <marker id="cmArrR" markerWidth="5" markerHeight="5" refX="4" refY="2.5" orient="auto"><path d="M0,0 L4.2,2.5 L0,5 Z" fill="var(--alert)" /></marker>
        </defs>
        <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
          {edges.map((e, i) => (
            <line key={i} x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2} stroke={e.color} strokeWidth={e.dashed ? 1.2 : 1.5}
              strokeDasharray={e.dashed ? "5 4" : undefined} opacity={op(e.appt)}
              markerEnd={e.color === "var(--s-net)" ? "url(#cmArrN)" : e.color === "var(--alert)" ? "url(#cmArrR)" : "url(#cmArrA)"}
              style={{ transition: "opacity .3s" }} />
          ))}
          {nodes.map((n) => {
            const active = n.id === sel;
            const activeStroke = active ? "var(--phosphor)" : n.stroke;
            return (
              <g key={n.id} onClick={() => pick(n.id)} onPointerDown={(e) => e.stopPropagation()} opacity={op(n.appt)}
                style={{ cursor: "pointer", transition: "opacity .3s" }}>
                {n.kind === "focus" ? (
                  <>
                    <ellipse cx={n.x} cy={n.y} rx={FOCUS_RX} ry={FOCUS_RY} fill="rgba(229,72,77,0.16)" stroke={activeStroke} strokeWidth={active ? 1.8 : 1.3} />
                    <text x={n.x} y={n.y - 3} textAnchor="middle" dominantBaseline="middle" className="cm-nlabel focus">{n.label}</text>
                    <text x={n.x} y={n.y + 9} textAnchor="middle" dominantBaseline="middle" className="cm-nsub" fill="var(--phosphor)">{n.sub}</text>
                  </>
                ) : n.kind === "ip" ? (
                  <>
                    <rect x={n.x - IP_W / 2} y={n.y - IP_H / 2} width={IP_W} height={IP_H} rx={IP_H / 2} fill="rgba(229,72,77,0.12)" stroke={activeStroke} strokeWidth={active ? 1.4 : 1} />
                    <circle cx={n.x - IP_W / 2 + 10} cy={n.y} r={2.5} fill="var(--alert)" />
                    <text x={n.x + 5} y={n.y} textAnchor="middle" dominantBaseline="middle" className="cm-nip">{n.label}</text>
                  </>
                ) : n.kind === "predicted" ? (
                  <>
                    <circle cx={n.x} cy={n.y} r={R_PRED} fill="rgba(229,72,77,0.08)" stroke={activeStroke} strokeWidth={active ? 1.4 : 1} strokeDasharray="4 3" />
                    <text x={n.x} y={n.y - 3} textAnchor="middle" dominantBaseline="middle" className="cm-nlabel pred" fill="var(--alert)">{n.label}</text>
                    <text x={n.x} y={n.y + 8} textAnchor="middle" dominantBaseline="middle" className="cm-nsub" fill="var(--haze)">{n.sub}</text>
                  </>
                ) : (
                  <>
                    <ellipse cx={n.x} cy={n.y} rx={HOST_RX} ry={HOST_RY} fill="var(--ink-2)" stroke={activeStroke} strokeWidth={active ? 1.6 : 1.1} />
                    <text x={n.x} y={n.y - 3} textAnchor="middle" dominantBaseline="middle" className="cm-nlabel host">{n.label}</text>
                    <text x={n.x} y={n.y + 8} textAnchor="middle" dominantBaseline="middle" className="cm-nsub" fill={n.subColor}>{n.sub}</text>
                  </>
                )}
              </g>
            );
          })}
        </g>
      </svg>
      <div className="cm-zoom">
        <button type="button" onClick={() => zoomBtn(1.25)} aria-label="zoom in">+</button>
        <button type="button" onClick={() => zoomBtn(1 / 1.25)} aria-label="zoom out">−</button>
        <button type="button" className="rst" onClick={reset} aria-label="reset view">reset</button>
      </div>
    </div>
  );
}

// ---- node detail ------------------------------------------------------------
function NodeDetail({ sel, focus, focusDetail, incCache, ipCache, attributed, onBlocked }: {
  sel: string; focus: IncidentSummary | null; focusDetail: IncidentDetail | null;
  incCache: Record<string, IncidentDetail>; ipCache: Record<string, NetworkDetail>;
  attributed: Set<string>; onBlocked: (ip: string) => void;
}) {
  const [busy, setBusy] = useState(false);

  if (sel.startsWith("ip:")) {
    const ip = sel.slice(3);
    const d = ipCache[ip];
    const listed = d?.reputation.listed;
    const block = async () => { setBusy(true); try { await addToBlocklist(ip, "blocked from attack map"); onBlocked(ip); } catch { /* ignore */ } finally { setBusy(false); } };
    return (
      <div className="cm-detail" style={{ borderLeftColor: "var(--alert)" }}>
        <div className="cm-detail-head">
          <span className="cm-detail-entity">{ip}</span>
          <span className={`cm-badge ${listed ? "bad" : "warn"}`}>{listed ? "C2 · ON BLOCKLIST" : "C2 · FLAGGED"}</span>
          <span className="spacer" /><span className="cm-detail-kind mono">external address</span>
        </div>
        <div className="cm-detail-cols">
          <div className="cm-evi">
            <div className="k mono">ENRICHMENT</div>
            {!d ? <div className="mono dim" style={{ fontSize: 11 }}>resolving…</div> : (
              <>
                <div className="cm-evrow"><span className="t mono">flows</span><span className="x">{d.flow_count} connections · {fmtBytes(d.total_bytes)} out</span></div>
                <div className="cm-evrow"><span className="t mono">intel</span><span className="x">{listed ? `on ${d.reputation.sources.length} blocklist${d.reputation.sources.length === 1 ? "" : "s"}: ${d.reputation.sources.join(", ")}` : (d.provider ? `${d.provider}${d.city ? ` · ${d.city}` : ""}` : "no offline record")}</span></div>
                {d.hosts.length > 0 && <div className="cm-evrow"><span className="t mono">hosts</span><span className="x">{d.hosts.join(", ")}</span></div>}
              </>
            )}
          </div>
          <div className="cm-vsep" />
          <div className="cm-meta-col">
            <div className="cm-metabox bad"><div className="k mono">EXPOSURE</div><div className="x">Active C2 destination for {focus?.entity ?? "the compromised host"}. Blocking installs one reversible firewall rule.</div></div>
            <button type="button" className="cm-cta armed" disabled={busy || listed} onClick={block}>
              {listed ? "already on blocklist" : busy ? "blocking…" : <>Block this address <Icon name="chevron" /></>}
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (sel === "predicted") {
    const nxt = focusDetail?.attribution.predicted_next ?? "";
    return (
      <div className="cm-detail" style={{ borderLeftColor: "var(--alert)" }}>
        <div className="cm-detail-head"><span className="cm-detail-entity">{nxt.replace(/_/g, " ")}</span><span className="cm-badge bad">PREDICTED NEXT</span><span className="spacer" /><span className="cm-detail-kind mono">forecast tactic</span></div>
        <div className="cm-metabox bad" style={{ marginTop: 4 }}><div className="k mono">WHY</div><div className="x">Learned from how ATT&CK tactics chain across intrusions — the most likely next move for {focus?.entity}. Prioritise detection and containment for this tactic now.</div></div>
      </div>
    );
  }

  // host / focus incident
  const isFocus = sel === focus?.id;
  const det = isFocus ? focusDetail : incCache[sel];
  const summ = isFocus ? focus : det?.summary ?? null;
  if (!summ) return <div className="cm-detail" style={{ borderLeftColor: "var(--line)" }}><div className="mono dim" style={{ fontSize: 12 }}>loading…</div></div>;
  const hi = summ.high_confidence;
  const accent = hi ? "var(--alert)" : summ.compound_score > 0.3 ? "var(--phosphor)" : "var(--haze)";
  const evidence = (det?.timeline ?? []).slice(-4);
  const predicted = det?.attribution.predicted_next ?? "";

  return (
    <div className="cm-detail" style={{ borderLeftColor: accent }}>
      <div className="cm-detail-head">
        <span className="cm-detail-entity">{summ.entity}</span>
        <span className={`cm-badge ${hi ? "hi" : "watch"}`}>{hi ? "● HIGH-CONFIDENCE" : "WATCH"}</span>
        {summ.is_true_positive && <span className="cm-badge rt">RED-TEAM CONFIRMED</span>}
        {(attributed.has(summ.id) || (det?.attribution.techniques.length ?? 0) > 0) && <span className="cm-badge attr">ATT&amp;CK MAPPED</span>}
        <span className="spacer" /><span className="cm-detail-kind mono">host · {summ.sources.join(" · ")}</span>
      </div>
      <div className="cm-chain mono">
        {summ.phases.map((ph, i) => (
          <span key={ph}>{i > 0 && <span className="dim"> ▸ </span>}<span style={{ color: PHASE_COLOR[ph] ?? "var(--haze)" }}>{ph.replace(/_/g, " ")}</span></span>
        ))}
      </div>
      <div className="cm-detail-cols">
        <div className="cm-evi">
          <div className="k mono">{hi ? "WHY — FUSED EVIDENCE" : "WHY — FLAGGED SIGNALS"}</div>
          {evidence.length === 0 ? <div className="mono dim" style={{ fontSize: 11 }}>loading timeline…</div> : evidence.map((e, i) => (
            <div className="cm-evrow" key={i}><span className="t mono">{clock(e.timestamp)}</span><span className="x">{e.detail} <span className="tag" style={{ color: PHASE_COLOR[e.phase] ?? "var(--haze)" }}>· {e.phase.replace(/_/g, " ")}</span></span></div>
          ))}
        </div>
        <div className="cm-vsep" />
        <div className="cm-meta-col">
          {predicted
            ? <div className="cm-metabox bad"><div className="k mono">PREDICTED NEXT</div><div className="x">{predicted.replace(/_/g, " ")} — blocking the C2 channel now closes the door it would use.</div></div>
            : <div className="cm-metabox"><div className="k mono">COMPOUND RISK</div><div className="x">{summ.compound_score.toFixed(2)} · {summ.source_count} sensors · {summ.phase_count} kill-chain phases.</div></div>}
          <Link href={`/incidents/${summ.id}`} className={`cm-cta${hi ? " armed" : ""}`}>{hi ? "Open response" : "Open incident"} <Icon name="chevron" /></Link>
        </div>
      </div>
    </div>
  );
}

// ---- rail bits --------------------------------------------------------------
function Sparkline({ series }: { series: ThroughputBucket[] }) {
  const buckets = series.slice(-22);
  const max = Math.max(1, ...buckets.map((b) => b.auth + b.process + b.network_flow));
  const dom = (b: ThroughputBucket) => b.network_flow >= b.auth && b.network_flow >= b.process ? "var(--s-net)" : b.process >= b.auth ? "var(--s-proc)" : "var(--s-auth)";
  return (
    <svg viewBox="0 0 204 46" className="cm-spark" role="img" aria-label="Ingest throughput">
      {buckets.map((b, i) => { const h = Math.max(2, ((b.auth + b.process + b.network_flow) / max) * 44); return <rect key={i} x={4 + i * 9} y={46 - h} width={6} height={h} rx={1} fill={dom(b)} />; })}
    </svg>
  );
}

function PipelineList({ status, warmup }: { status: Status | null; warmup: boolean }) {
  const rows = [
    { name: "baseline", slug: "ingest", ...(status?.baseline_ready ? { s: "frozen", c: "var(--calm)" } : warmup ? { s: "warming", c: "var(--phosphor)" } : { s: "guardrails", c: "var(--haze)" }) },
    { name: "sentinel", slug: "detect", s: "screening", c: "var(--calm)" },
    { name: "correlator", slug: "correlate", ...((status?.incident_count ?? 0) > 0 ? { s: `${status!.incident_count} open`, c: "var(--phosphor)" } : { s: "idle", c: "var(--haze)" }) },
    { name: "attribution", slug: "attribute", ...(status?.pipeline?.attribution_error ? { s: "error", c: "var(--alert)" } : { s: "mapping", c: "var(--calm)" }) },
    { name: "responder", slug: "respond", ...((status?.response?.pending ?? 0) > 0 ? { s: `${status!.response.pending} awaiting`, c: "var(--alert)" } : { s: "idle", c: "var(--haze)" }) },
  ];
  return (
    <div>
      <div className="cm-rail-lbl2">Pipeline</div>
      <div className="cm-pipe">
        {rows.map((r) => (
          <Link key={r.name} href={`/pipeline/${r.slug}`} className="cm-piperow">
            <span className="cm-pdot" style={{ background: r.c }} /><span className="cm-pname mono">{r.name}</span><span className="cm-pstate mono" style={{ color: r.c }}>{r.s}</span>
          </Link>
        ))}
      </div>
    </div>
  );
}
