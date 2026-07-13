"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { getStatus, type IncidentSummary, type Status } from "../lib/api";
import { subscribe } from "../lib/stream";

function IncidentRow({ i }: { i: IncidentSummary }) {
  return (
    <Link href={`/incidents/${i.id}`} className={`inc-row${i.is_true_positive ? " tp" : ""}`}>
      <div className="entity"><span className="lbl">ENTITY</span>{i.entity}</div>
      <div>
        <div className="meta">
          {i.high_confidence && <span className="pill hi">● HIGH-CONFIDENCE</span>}
          {i.is_true_positive && <span className="pill rt">RED-TEAM CONFIRMED</span>}
          {!i.high_confidence && !i.is_true_positive && <span className="pill calm">watch</span>}
        </div>
        <div className="facts">
          <b>{i.source_count}</b> sensors · <b>{i.phase_count}</b> kill-chain phases · <b>{i.event_count}</b> events
        </div>
        <div className="meter"><span style={{ width: `${Math.round(i.compound_score * 100)}%` }} /></div>
      </div>
      <div className="score">
        <div className="v">{i.compound_score.toFixed(2)}</div>
        <div className="c">compound</div>
      </div>
    </Link>
  );
}

function Banner({ status, active }: { status: Status | null; active: boolean }) {
  if (!status) return null;
  if (status.mode === "warmup") {
    const s = Math.max(0, Math.round(status.warmup_remaining_s));
    const mmss = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
    return <div className="livebar warm"><span className="dot" />Learning normal… {mmss}</div>;
  }
  return (
    <div className={`livebar${active ? " alert" : ""}`}>
      <span className="dot" />Monitoring · {status.events_seen.toLocaleString()} events
      {active && <b> · active incident</b>}
    </div>
  );
}

export function LiveConsole({ initial }: { initial: IncidentSummary[] }) {
  const [incidents, setIncidents] = useState<IncidentSummary[]>(initial);
  const [status, setStatus] = useState<Status | null>(null);

  useEffect(() => {
    const unsub = subscribe((e) => {
      if (e.type === "incident") {
        const inc = e as IncidentSummary;
        setIncidents((prev) => {
          const next = prev.filter((p) => p.id !== inc.id).concat(inc);
          next.sort((a, b) => b.compound_score - a.compound_score);
          return next;
        });
      }
    });
    const poll = setInterval(() => { getStatus().then(setStatus).catch(() => {}); }, 2000);
    getStatus().then(setStatus).catch(() => {});
    return () => { unsub(); clearInterval(poll); };
  }, []);

  const active = incidents.some((i) => i.high_confidence);

  return (
    <>
      <Banner status={status} active={active} />
      {incidents.length > 0 ? (
        <div className="inc-list">
          {incidents.map((i) => <IncidentRow key={i.id} i={i} />)}
        </div>
      ) : (
        <p style={{ color: "var(--haze)" }}>No active incidents — monitoring live telemetry.</p>
      )}
    </>
  );
}
