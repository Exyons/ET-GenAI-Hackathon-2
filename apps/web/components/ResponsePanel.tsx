"use client";

import { useCallback, useEffect, useState } from "react";

import {
  approveAction, getActions, PLAYBOOK_TITLE, rejectAction, revertAction,
  type ResponseAction,
} from "../lib/api";

const READ_ONLY = new Set(["snapshot"]);

const STATUS_LABEL: Record<string, string> = {
  pending_approval: "AWAITING APPROVAL",
  approved: "APPROVED · dispatching",
  dispatched: "RUNNING ON HOST",
  executed: "EXECUTED",
  failed: "FAILED",
  rejected: "REJECTED",
  reverted: "REVERTED",
};

function Result({ a }: { a: ResponseAction }) {
  const r = a.result;
  if (!r) return null;
  return (
    <div className={`act-result${r.error ? " err" : ""}`}>
      {r.command && <div className="cmd mono">$ {r.command}</div>}
      {r.note && <div className="note mono">{r.note}</div>}
      {r.stdout && <pre className="stdout mono">{r.stdout}</pre>}
      {r.error && <div className="note mono err">error: {r.error}</div>}
      <div className="tag mono">{r.dry_run ? "DRY-RUN — nothing changed on the host" : "LIVE — executed on host"}</div>
    </div>
  );
}

function ActionCard({ a, onChange }: { a: ResponseAction; onChange: () => void }) {
  const [busy, setBusy] = useState(false);
  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try { await fn(); } finally { setBusy(false); onChange(); }
  };
  const pending = a.status === "pending_approval";
  const inFlight = a.status === "approved" || a.status === "dispatched";
  const readOnly = READ_ONLY.has(a.playbook);
  const canRevert = a.status === "executed" && a.reversible && !readOnly
    && !a.result?.dry_run && !a.undo;

  return (
    <div className={`act-card st-${a.status}`}>
      <div className="act-head">
        <div className="act-title">
          {PLAYBOOK_TITLE[a.playbook] ?? a.playbook}
          <span className="act-target mono">{a.target}</span>
          {readOnly
            ? <span className="act-rev">read-only</span>
            : a.reversible ? <span className="act-rev">reversible</span> : <span className="act-irrev">irreversible</span>}
          {a.undo && <span className="act-rev">undo</span>}
        </div>
        <span className={`act-status mono st-${a.status}`}>{STATUS_LABEL[a.status] ?? a.status}</span>
      </div>
      <div className="act-reason">{a.reason}</div>
      {a.approver && a.status !== "pending_approval" && (
        <div className="act-meta mono">
          {a.mode === "armed" ? "armed" : "dry-run"} · approver {a.approver}
        </div>
      )}
      <Result a={a} />
      <div className="act-buttons">
        {pending && (
          <>
            <button type="button" className="btn go" disabled={busy}
              onClick={() => act(() => approveAction(a.id, false))}>Approve · dry-run ▸</button>
            <button type="button" className="btn arm" disabled={busy}
              onClick={() => act(() => approveAction(a.id, true))}>Arm &amp; approve ⚠</button>
            <button type="button" className="btn no" disabled={busy}
              onClick={() => act(() => rejectAction(a.id))}>Reject</button>
          </>
        )}
        {inFlight && <span className="act-wait mono">waiting for agent on {a.host}…</span>}
        {canRevert && (
          <button type="button" className="btn rev" disabled={busy}
            onClick={() => act(() => revertAction(a.id))}>Revert ↩</button>
        )}
      </div>
    </div>
  );
}

export function ResponsePanel({ incidentId }: { incidentId: string }) {
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const load = useCallback(() => {
    getActions(incidentId).then(setActions).catch(() => {});
  }, [incidentId]);

  useEffect(() => {
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [load]);

  const pending = actions.filter((a) => a.status === "pending_approval").length;

  return (
    <div className="panel respanel">
      <h2>
        Response <span className="hint">— recommended containment · human gate</span>
        <span className="spacer" />
        {pending > 0 && <span className="pill hi">{pending} awaiting approval</span>}
      </h2>
      <div className="pad">
        {actions.length === 0 ? (
          <p className="mono dim" style={{ fontSize: 12.5 }}>
            No response actions — recommendations appear here when this incident is high-confidence.
          </p>
        ) : (
          <>
            <p className="gate-note">
              Nothing runs until you approve. <b>Approve · dry-run</b> reports the exact command without
              touching the host; <b>Arm &amp; approve</b> executes for real (and still requires the agent to
              be started with <span className="mono">PRAHARI_ALLOW_ARMED=true</span>).
            </p>
            <div className="act-list">
              {actions.map((a) => <ActionCard key={a.id} a={a} onChange={load} />)}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
