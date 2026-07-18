"use client";

import Link from "next/link";
import { useEffect, useRef } from "react";

import type { Status } from "../lib/api";
import { clock } from "../lib/format";
import type { StageDef } from "../lib/pipeline";
import { Icon } from "./Icon";

export function StageModal({ stage, status, onClose }: {
  stage: StageDef; status: Status | null; onClose: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const st = stage.state(status);
  const err = stage.error?.(status);
  const recent = (status?.pipeline?.activity ?? [])
    .filter((a) => a.stage === stage.activityStage)
    .slice(-5)
    .reverse();

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className={`modal ${stage.cls}`} role="dialog" aria-modal="true" aria-label={stage.name}
        onClick={(e) => e.stopPropagation()}>
        <div className="modal-accent" />
        <div className="modal-head">
          <div>
            <div className="modal-eyebrow mono">PIPELINE STAGE · {stage.word.toUpperCase()}</div>
            <h3 className="modal-title">{stage.name}</h3>
          </div>
          <span className={`stage-state mono${st.tone ? ` ${st.tone}` : ""}`}>{st.label}</span>
        </div>

        <p className="modal-about">{stage.about}</p>

        <div className="modal-metrics">
          {stage.lines(status).map(([k, v]) => (
            <div key={k} className="mm">
              <div className="mm-k">{k}</div>
              <div className="mm-v mono">{v}</div>
            </div>
          ))}
        </div>

        {err && <div className="modal-err mono"><Icon name="warn" /> {err}</div>}

        {stage.activityStage && (
          <div className="modal-activity">
            <div className="modal-sub mono">RECENT · {stage.word}</div>
            {recent.length === 0 ? (
              <div className="mono dim" style={{ fontSize: 11.5 }}>no activity yet</div>
            ) : (
              recent.map((a, i) => (
                <div key={`${a.t}-${i}`} className="modal-log mono">
                  <span className="t">{clock(a.t)}</span>
                  <span className="m">{a.msg}</span>
                </div>
              ))
            )}
          </div>
        )}

        <div className="modal-foot">
          <Link href={`/pipeline/${stage.slug}`} className="btn go">Full details ▸</Link>
          <button type="button" ref={closeRef} className="btn no" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
