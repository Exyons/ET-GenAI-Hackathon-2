"use client";

import { useState } from "react";

import type { ThroughputBucket } from "../lib/api";

const W = 720;                 // 36 slots × 20
const H = 92;
const SLOT = 20;
const BAR = 14;
const GAP = 2;                 // surface gap between stacked segments
const SERIES = [
  { key: "auth", label: "AUTH", cls: "s-auth" },
  { key: "process", label: "PROCESS", cls: "s-proc" },
  { key: "network_flow", label: "NETWORK", cls: "s-net" },
] as const;

function topRoundedRect(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.min(r, h, w / 2);
  return `M${x},${y + h} v${-(h - rr)} q0,${-rr} ${rr},${-rr} h${w - 2 * rr} q${rr},0 ${rr},${rr} v${h - rr} z`;
}

export function Throughput({ series, hasSensors }: { series: ThroughputBucket[]; hasSensors: boolean }) {
  const [hover, setHover] = useState<number | null>(null);

  const buckets = series.slice(-36);
  const totals = buckets.map((b) => b.auth + b.process + b.network_flow);
  const peak = Math.max(...totals, 0);
  const scale = (H - 10) / Math.max(peak, 5);
  const quiet = peak === 0;

  return (
    <section className="panel">
      <h2>
        Ingest throughput <span className="hint">— last 6 min · 10s buckets</span>
        <span className="spacer" />
        <span className="legend">
          {SERIES.map((s) => (
            <span key={s.key} className="key">
              <i className={`swatch ${s.cls}`} />
              {s.label}
            </span>
          ))}
          <span className="peak mono">peak {peak}/10s</span>
        </span>
      </h2>
      <div className="chart" onMouseLeave={() => setHover(null)}>
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-label="Event throughput by type, last 6 minutes">
          <line x1={0} y1={H - 0.5} x2={W} y2={H - 0.5} className="baseline" />
          {buckets.map((b, i) => {
            const x = i * SLOT + (SLOT - BAR) / 2;
            let y = H;
            const segs: React.ReactNode[] = [];
            const stack = SERIES.map((s) => ({ ...s, v: b[s.key] })).filter((s) => s.v > 0);
            stack.forEach((s, si) => {
              const h = Math.max(s.v * scale, 2);
              const yTop = y - h;
              const last = si === stack.length - 1;
              segs.push(
                last ? (
                  <path key={s.key} d={topRoundedRect(x, yTop, BAR, h, 3)} className={`fill-${s.cls}`} />
                ) : (
                  <rect key={s.key} x={x} y={yTop} width={BAR} height={h} className={`fill-${s.cls}`} />
                ),
              );
              y = yTop - GAP;
            });
            return (
              <g key={b.t}>
                {hover === i && <rect x={i * SLOT} y={0} width={SLOT} height={H} className="hoverband" />}
                {segs}
                <rect
                  x={i * SLOT} y={0} width={SLOT} height={H} fill="transparent"
                  onMouseEnter={() => setHover(i)}
                />
              </g>
            );
          })}
        </svg>
        {quiet && (
          <div className="quiet mono">
            {hasSensors
              ? "sensors connected · no events in the last 6 min — generate some: ssh localhost, sudo -v, run commands"
              : "awaiting telemetry — start a collector or the demo feed"}
          </div>
        )}
        {hover !== null && buckets[hover] && (
          <div
            className="tip mono"
            style={{ left: `${((hover + 0.5) / 36) * 100}%` }}
            role="status"
          >
            <div className="t">{new Date(buckets[hover].t * 1000).toISOString().slice(11, 19)} UTC</div>
            {SERIES.map((s) => (
              <div key={s.key} className="row">
                <i className={`swatch ${s.cls}`} />
                {s.label.toLowerCase()} <b>{buckets[hover][s.key]}</b>
              </div>
            ))}
          </div>
        )}
        <div className="xaxis mono">
          <span>-6m</span>
          <span>-3m</span>
          <span>now</span>
        </div>
      </div>
    </section>
  );
}
