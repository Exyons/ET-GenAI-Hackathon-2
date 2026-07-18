"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import {
  approveAction, getActions, getPlaybooks, PLAYBOOK_TITLE, rejectAction, revertAction,
  type PlaybookInfo, type ResponseAction,
} from "../lib/api";
import { Help } from "./Help";
import { Icon } from "./Icon";
import { IpChip } from "./IpChip";

// status filters and the order playbook groups are shown in
type FilterKey = "all" | "pending" | "active" | "done" | "dismissed";
const FILTERS: { key: FilterKey; label: string; match: (a: ResponseAction) => boolean }[] = [
  { key: "all", label: "All", match: () => true },
  { key: "pending", label: "Awaiting", match: (a) => a.status === "pending_approval" },
  { key: "active", label: "Running", match: (a) => a.status === "approved" || a.status === "dispatched" },
  { key: "done", label: "Executed", match: (a) => a.status === "executed" },
  { key: "dismissed", label: "Dismissed", match: (a) => ["rejected", "reverted", "failed"].includes(a.status) },
];
const PLAYBOOK_ORDER = ["isolate_host", "block_ip", "disable_account", "kill_process", "snapshot"];

const READ_ONLY = new Set(["snapshot"]);
const IP_TARGET = new Set(["block_ip"]);

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
  const readOnly = READ_ONLY.has(a.playbook);
  return (
    <div className={`act-result${r.error ? " err" : ""}`}>
      {r.command && <div className="cmd mono">$ {r.command}</div>}
      {r.note && <div className="note mono">{r.note}</div>}
      {r.stdout && <pre className="stdout mono">{r.stdout}</pre>}
      {r.error && <div className="note mono err">error: {r.error}</div>}
      <div className="tag mono">
        {readOnly ? "READ-ONLY — evidence collected, host unchanged"
          : r.dry_run ? "DRY-RUN — this is what WOULD run; nothing changed on the host"
            : "LIVE — executed on host"}
      </div>
    </div>
  );
}

function ActionCard({ a, info, onChange }: {
  a: ResponseAction; info?: PlaybookInfo; onChange: () => void;
}) {
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
          {info?.title ?? PLAYBOOK_TITLE[a.playbook] ?? a.playbook}
          {IP_TARGET.has(a.playbook) ? <IpChip ip={a.target} /> : <span className="act-target mono">{a.target}</span>}
          {readOnly
            ? <span className="act-rev">read-only<Help align="right" text="Read-only actions only collect evidence — they can't harm the host, so they run immediately when approved. There is no separate Arm step (that gate exists only for destructive actions)." wide /></span>
            : a.reversible ? <span className="act-rev">reversible</span> : <span className="act-irrev">irreversible</span>}
          {a.undo && <span className="act-rev">undo</span>}
        </div>
        <span className={`act-status mono st-${a.status}`}>{STATUS_LABEL[a.status] ?? a.status}</span>
      </div>

      <div className="act-reason">{a.reason}</div>

      {info && (
        <div className="act-explain">
          <div className="ae-row"><span className="ae-k">What it does</span><span className="ae-v">{info.what}</span></div>
          <div className="ae-row"><span className="ae-k">Impact</span><span className="ae-v">{info.impact}</span></div>
        </div>
      )}

      {a.approver && a.status !== "pending_approval" && (
        <div className="act-meta mono">{a.mode === "armed" ? "armed" : "dry-run"} · approver {a.approver}</div>
      )}
      <Result a={a} />

      <div className="act-buttons">
        {pending && (
          <>
            <button type="button" className="btn go" disabled={busy}
              onClick={() => act(() => approveAction(a.id, false))}>
              {readOnly ? "Approve · run" : "Approve · dry-run"} <Icon name="chevron" />
            </button>
            {!readOnly && (
              <button type="button" className="btn arm" disabled={busy}
                onClick={() => act(() => approveAction(a.id, true))}>Arm &amp; approve <Icon name="warn" /></button>
            )}
            <button type="button" className="btn no" disabled={busy}
              onClick={() => act(() => rejectAction(a.id))}>Reject</button>
          </>
        )}
        {inFlight && <span className="act-wait mono">waiting for agent on {a.host}…</span>}
        {canRevert && (
          <button type="button" className="btn rev" disabled={busy}
            onClick={() => act(() => revertAction(a.id))}>Revert <Icon name="undo" /></button>
        )}
      </div>
    </div>
  );
}

// horizontally-scrollable carousel of action cards — keeps a long list of similar
// actions (e.g. many block-address proposals) from stacking down the page
function Carousel({ children, count }: { children: React.ReactNode; count: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const scroll = (dir: 1 | -1) => {
    const el = ref.current;
    if (el) el.scrollBy({ left: dir * Math.max(300, el.clientWidth * 0.85), behavior: "smooth" });
  };
  return (
    <div className="act-carousel">
      {count > 1 && (
        <button type="button" className="caro-nav prev" aria-label="previous" onClick={() => scroll(-1)}>
          <Icon name="chevron" dir="left" />
        </button>
      )}
      <div className="caro-track" ref={ref}>{children}</div>
      {count > 1 && (
        <button type="button" className="caro-nav next" aria-label="next" onClick={() => scroll(1)}>
          <Icon name="chevron" dir="right" />
        </button>
      )}
    </div>
  );
}

function groupByPlaybook(actions: ResponseAction[]): [string, ResponseAction[]][] {
  const groups = new Map<string, ResponseAction[]>();
  for (const a of actions) (groups.get(a.playbook) ?? groups.set(a.playbook, []).get(a.playbook)!).push(a);
  return [...groups.entries()].sort(
    ([a], [b]) => (PLAYBOOK_ORDER.indexOf(a) + 1 || 99) - (PLAYBOOK_ORDER.indexOf(b) + 1 || 99),
  );
}

export function ResponsePanel({ incidentId }: { incidentId: string }) {
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [catalog, setCatalog] = useState<Record<string, PlaybookInfo>>({});
  const [filter, setFilter] = useState<FilterKey>("all");
  const load = useCallback(() => {
    getActions(incidentId).then(setActions).catch(() => {});
  }, [incidentId]);

  useEffect(() => {
    load();
    getPlaybooks().then(setCatalog).catch(() => {});
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [load]);

  const pending = actions.filter((a) => a.status === "pending_approval").length;
  const shown = actions.filter(FILTERS.find((f) => f.key === filter)!.match);
  const groups = groupByPlaybook(shown);

  return (
    <div className="panel respanel">
      <h2>
        Response
        <Help wide text="Recommended containment for this incident. Nothing runs until you approve at the human gate. Approve · dry-run reports the exact command without touching the host; Arm & approve executes for real (and still needs the agent started with PRAHARI_ALLOW_ARMED=true). Read-only actions have no arm step." />
        <span className="hint">— containment · human gate</span>
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
              Nothing runs until you approve. <b>Approve · dry-run</b> reports the command without touching
              the host; <b>Arm &amp; approve</b> executes for real. Read-only actions skip the arm step —
              they only collect evidence.
            </p>
            <div className="act-filters">
              {FILTERS.map((f) => {
                const n = actions.filter(f.match).length;
                return (
                  <button key={f.key} type="button"
                    className={`act-filter mono${filter === f.key ? " on" : ""}`}
                    onClick={() => setFilter(f.key)}>
                    {f.label} <span className="n">{n}</span>
                  </button>
                );
              })}
            </div>
            {groups.length === 0 ? (
              <p className="mono dim" style={{ fontSize: 12.5 }}>No actions match this filter.</p>
            ) : groups.map(([playbook, items]) => {
              const grpPending = items.filter((a) => a.status === "pending_approval").length;
              return (
                <div className="act-group" key={playbook}>
                  <div className="act-group-head mono">
                    <span className="gt">{PLAYBOOK_TITLE[playbook] ?? playbook}</span>
                    <span className="gc">{items.length}{items.length === 1 ? " action" : " actions"}
                      {grpPending > 0 ? ` · ${grpPending} awaiting` : ""}</span>
                  </div>
                  <Carousel count={items.length}>
                    {items.map((a) => (
                      <div className="caro-item" key={a.id}>
                        <ActionCard a={a} info={catalog[a.playbook]} onChange={load} />
                      </div>
                    ))}
                  </Carousel>
                </div>
              );
            })}
          </>
        )}
      </div>
    </div>
  );
}
