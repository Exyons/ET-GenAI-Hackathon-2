"use client";

import { useState } from "react";

import type { Status } from "../lib/api";
import { clock } from "../lib/format";
import { STAGES, type StageDef } from "../lib/pipeline";
import { StageModal } from "./StageModal";

const STAGE_CLS: Record<string, string> = {
  baseline: "st-base",
  sentinel: "st-sent",
  correlator: "st-corr",
  attribution: "st-attr",
  responder: "st-resp",
};

function StageCard({ stage, status, onOpen }: {
  stage: StageDef; status: Status | null; onOpen: () => void;
}) {
  const st = stage.state(status);
  const err = stage.error?.(status);
  return (
    <button type="button" className={`stage ${stage.cls}`} onClick={onOpen}
      aria-label={`${stage.name} — open details`}>
      <div className="stage-head">
        <span className="stage-name">{stage.name}</span>
        {st.label && <span className={`stage-state mono${st.tone ? ` ${st.tone}` : ""}`}>{st.label}</span>}
      </div>
      {stage.lines(status).map(([k, v]) => (
        <div key={k} className="stage-line mono"><span className="k">{k}</span><span className="v">{v}</span></div>
      ))}
      {err && <div className="stage-err mono" title={err}>{err}</div>}
      <span className="stage-open mono" aria-hidden>details →</span>
    </button>
  );
}

export function PipelineMonitor({ status }: { status: Status | null }) {
  const [open, setOpen] = useState<StageDef | null>(null);
  const activity = status?.pipeline?.activity ?? [];

  return (
    <section className="panel pipemon">
      <h2>
        Pipeline <span className="hint">— collect → screen → detect → correlate → attribute → respond</span>
        <span className="spacer" />
        <span className="hint mono">click any stage · live</span>
      </h2>
      <div className="stages">
        {STAGES.map((stage) => (
          <StageCard key={stage.slug} stage={stage} status={status} onOpen={() => setOpen(stage)} />
        ))}
      </div>
      <div className="pipelog">
        {activity.length === 0 ? (
          <div className="stage-line mono dim" style={{ padding: "8px 16px" }}>no pipeline activity yet</div>
        ) : (
          [...activity].reverse().slice(0, 9).map((a, i) => (
            <div key={`${a.t}-${i}`} className="logline mono">
              <span className="t">{clock(a.t)}</span>
              <span className={`stagechip ${STAGE_CLS[a.stage] ?? ""}`}>{a.stage.toUpperCase()}</span>
              <span className="m">{a.msg}</span>
            </div>
          ))
        )}
      </div>
      {open && <StageModal stage={open} status={status} onClose={() => setOpen(null)} />}
    </section>
  );
}
