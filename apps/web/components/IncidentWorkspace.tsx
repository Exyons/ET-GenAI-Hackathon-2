"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  approveAction, getActions, getIncident, getNetworkDetail, getPlaybooks, PLAYBOOK_TITLE,
  rejectAction, revertAction,
  type Forensics, type IncidentDetail, type NetworkDetail, type PlaybookInfo, type ResponseAction,
} from "../lib/api";
import { Icon } from "./Icon";
import { ThemeToggle } from "./ThemeToggle";

// ---- static maps ------------------------------------------------------------
const PHASE_COLOR: Record<string, string> = {
  lateral_movement: "var(--s-auth)", discovery: "var(--s-proc)", execution: "var(--s-proc)",
  command_and_control: "var(--s-net)", exfiltration: "var(--alert)",
};
const PLAYBOOK_DOT: Record<string, string> = {
  isolate_host: "var(--alert)", block_ip: "var(--phosphor)", disable_account: "var(--s-auth)",
  kill_process: "var(--alert)", snapshot: "var(--calm)",
};
const READ_ONLY = new Set(["snapshot"]);

function clock(iso: string): string { return new Date(iso).toISOString().slice(11, 19); }
function fmtBytes(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} MB`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)} KB`;
  return `${n} B`;
}

// ---- decision model (derived from live actions) -----------------------------
type DStatus = "pending" | "running" | "dry_done" | "live_done" | "failed" | "rejected" | "reverted" | "mixed";

function childPhase(a: ResponseAction): DStatus {
  switch (a.status) {
    case "pending_approval": return "pending";
    case "approved": case "dispatched": return "running";
    case "executed": return a.result?.dry_run ? "dry_done" : "live_done";
    case "failed": return "failed";
    case "rejected": return "rejected";
    case "reverted": return "reverted";
    default: return "mixed";
  }
}
function rollUp(actions: ResponseAction[]): DStatus {
  const ph = actions.map(childPhase);
  for (const s of ["pending", "running", "live_done", "dry_done", "failed"] as DStatus[]) {
    if (ph.includes(s)) return s;
  }
  if (ph.every((s) => s === "rejected")) return "rejected";
  if (ph.every((s) => s === "reverted")) return "reverted";
  return "mixed";
}

type Decision = {
  key: string; playbook: string; title: string; sub: string; dot: string;
  readOnly: boolean; reversible: boolean; reason: string;
  actions: ResponseAction[]; status: DStatus;
  tier: number; escalation: boolean; gateNote: string;
};

const TIER_LABEL = ["observe", "precision", "vector", "isolate"];

const STATUS_META: Record<DStatus, { label: string; color: string }> = {
  pending: { label: "AWAITING APPROVAL", color: "var(--phosphor)" },
  running: { label: "DISPATCHED · ON HOST", color: "var(--s-auth)" },
  dry_done: { label: "EXECUTED · DRY-RUN", color: "var(--calm)" },
  live_done: { label: "EXECUTED · LIVE", color: "var(--calm)" },
  failed: { label: "FAILED", color: "var(--alert)" },
  rejected: { label: "REJECTED", color: "var(--haze)" },
  reverted: { label: "REVERTED", color: "var(--haze)" },
  mixed: { label: "IN PROGRESS", color: "var(--haze)" },
};

function buildDecisions(actions: ResponseAction[], catalog: Record<string, PlaybookInfo>, entity: string): Decision[] {
  const blocks = actions.filter((a) => a.playbook === "block_ip");
  const out: Decision[] = [];

  // isolate / disable / kill / snapshot — one decision per action
  for (const a of actions.filter((x) => x.playbook !== "block_ip")) {
    out.push({
      key: a.id, playbook: a.playbook, actions: [a],
      title: catalog[a.playbook]?.title ?? PLAYBOOK_TITLE[a.playbook] ?? a.playbook,
      sub: READ_ONLY.has(a.playbook) ? "read-only · safe" : a.reversible ? "reversible" : "irreversible",
      dot: PLAYBOOK_DOT[a.playbook] ?? "var(--haze)",
      readOnly: READ_ONLY.has(a.playbook), reversible: a.reversible,
      reason: a.reason, status: childPhase(a),
      tier: a.tier ?? 1, escalation: a.escalation ?? false, gateNote: a.gate_note ?? "",
    });
  }
  // block_ip — aggregate all addresses into one decision
  if (blocks.length > 0) {
    out.push({
      key: "block", playbook: "block_ip", actions: blocks,
      title: `Block ${blocks.length} address${blocks.length === 1 ? "" : "es"}`,
      sub: `${blocks.length} outbound channel${blocks.length === 1 ? "" : "s"} · reversible`,
      dot: "var(--phosphor)", readOnly: false, reversible: true,
      reason: `${entity} opened outbound channels to these addresses during the incident. One firewall rule per address — everything else on the host keeps working. Untick any address you want to leave open.`,
      status: rollUp(blocks),
      tier: blocks[0].tier ?? 1, escalation: false, gateNote: "",
    });
  }
  // pending first, then least-disruptive first — the ladder decides the order,
  // so an escalation can never sit at the top of the queue
  return out.sort((a, b) => {
    const ap = a.status === "pending" ? 0 : 1, bp = b.status === "pending" ? 0 : 1;
    if (ap !== bp) return ap - bp;
    if (a.escalation !== b.escalation) return a.escalation ? 1 : -1;
    return a.tier - b.tier;
  });
}

// ---- IP enrichment (cached) --------------------------------------------------
function useEnrichment(ips: string[]): Record<string, NetworkDetail> {
  const [cache, setCache] = useState<Record<string, NetworkDetail>>({});
  const requested = useRef<Set<string>>(new Set());
  const key = ips.join(",");
  useEffect(() => {
    for (const ip of ips) {
      if (requested.current.has(ip)) continue;
      requested.current.add(ip);
      getNetworkDetail(ip).then((d) => setCache((c) => ({ ...c, [ip]: d }))).catch(() => requested.current.delete(ip));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return cache;
}

// ---- header clock ------------------------------------------------------------
function useClock(): string {
  const [t, setT] = useState("--:--:--");
  useEffect(() => {
    const tick = () => setT(new Date().toISOString().slice(11, 19));
    tick();
    const h = setInterval(tick, 1000);
    return () => clearInterval(h);
  }, []);
  return t;
}

export function IncidentWorkspace({ id }: { id: string }) {
  const [d, setD] = useState<IncidentDetail | null>(null);
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [catalog, setCatalog] = useState<Record<string, PlaybookInfo>>({});
  const [error, setError] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const [mode, setMode] = useState<"dry" | "armed">("dry");
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const utc = useClock();

  const load = useCallback(() => {
    getActions(id).then(setActions).catch(() => {});
    getIncident(id).then(setD).catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [id]);
  useEffect(() => {
    load();
    getPlaybooks().then(setCatalog).catch(() => {});
    const t = setInterval(load, 4000); // deliberately slow — the LLM needs time to fill attribution
    return () => clearInterval(t);
  }, [load]);

  const entity = d?.summary.entity ?? id;
  const decisions = useMemo(() => buildDecisions(actions, catalog, entity), [actions, catalog, entity]);
  // escalations are actions the evidence does NOT yet justify — they stay out of
  // the decision queue so "isolate everything" never reads as the default move
  const pending = decisions.filter((x) => x.status === "pending" && !x.escalation);
  const escalations = decisions.filter((x) => x.status === "pending" && x.escalation);
  const resolved = decisions.filter((x) => x.status !== "pending");

  // default selection: first pending, else first
  useEffect(() => {
    if (decisions.length === 0) { setSel(null); return; }
    if (!sel || !decisions.some((x) => x.key === sel)) setSel((pending[0] ?? decisions[0]).key);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [decisions.map((x) => x.key).join(",")]);

  const current = decisions.find((x) => x.key === sel) ?? null;
  const blockIps = current?.playbook === "block_ip" ? current.actions.map((a) => a.target) : [];
  const enrich = useEnrichment(blockIps);

  const awaiting = pending.reduce((n, x) =>
    n + x.actions.filter((a) => childPhase(a) === "pending" && !excluded.has(a.id)).length, 0);

  // ---- action helpers -------------------------------------------------------
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try { await fn(); } finally { setBusy(false); load(); }
  };
  const selectedPending = (dec: Decision) =>
    dec.actions.filter((a) => childPhase(a) === "pending" && !excluded.has(a.id));
  const approve = (dec: Decision, armed: boolean) =>
    run(() => Promise.all(selectedPending(dec).map((a) => approveAction(a.id, armed))));
  const reject = (dec: Decision) =>
    run(() => Promise.all(dec.actions.filter((a) => childPhase(a) === "pending").map((a) => rejectAction(a.id))));
  const revert = (dec: Decision) =>
    run(() => Promise.all(dec.actions
      .filter((a) => childPhase(a) === "live_done" && a.reversible && !a.undo)
      .map((a) => revertAction(a.id))));
  const armForReal = (dec: Decision) =>
    run(() => Promise.all(dec.actions.filter((a) => childPhase(a) === "dry_done").map((a) => approveAction(a.id, true))));

  if (!d && error) {
    return (
      <div className="iw">
        <Header entity={id} score={0} awaiting={0} utc={utc} />
        <p className="mono" style={{ color: "var(--haze)", padding: 28 }}>Incident unavailable — {error}</p>
      </div>
    );
  }
  const s = d?.summary;
  const attr = d?.attribution;
  const phases = d ? [...new Set(d.timeline.map((e) => e.phase))] : [];

  return (
    <div className="iw">
      <Header entity={s?.entity ?? id} score={s?.compound_score ?? 0} awaiting={awaiting} utc={utc}
        highConfidence={s?.high_confidence} />

      <div className={`iw-body${attr ? "" : " no-rail"}`}>
        {/* ---- queue ---- */}
        <div className="iw-queue">
          <div className="iw-queue-head">NEEDS DECISION · {pending.length}</div>
          {pending.length === 0 && (
            <div className="iw-empty ok">All decisions made — nothing waiting on you.</div>
          )}
          {pending.map((dec) => (
            <QueueRow key={dec.key} dec={dec} active={dec.key === sel} onClick={() => setSel(dec.key)} />
          ))}

          {escalations.length > 0 && (
            <>
              <div className="iw-queue-head divider">LAST RESORT · {escalations.length}</div>
              <div className="iw-esc-note">
                Available, but not recommended on the current evidence. Open one to see what
                covers it instead.
              </div>
              {escalations.map((dec) => (
                <QueueRow key={dec.key} dec={dec} active={dec.key === sel} onClick={() => setSel(dec.key)} />
              ))}
            </>
          )}

          <div className="iw-queue-head divider">RESOLVED · {resolved.length}</div>
          {resolved.length === 0 ? (
            <div className="iw-empty">Decisions you approve or reject move here with their outcome.</div>
          ) : resolved.map((dec) => (
            <QueueRow key={dec.key} dec={dec} active={dec.key === sel} onClick={() => setSel(dec.key)} resolved />
          ))}

          <div className="iw-gate">
            <div className="iw-gate-k mono">HUMAN GATE</div>
            <div className="iw-gate-t">Nothing runs until you approve. Dry-run never touches the host.</div>
          </div>
        </div>

        {/* ---- detail ---- */}
        <div className="iw-detail">
          {!current ? (
            <p className="mono" style={{ color: "var(--haze)" }}>
              {actions.length === 0 ? "No response actions yet — recommendations appear here when the incident is high-confidence." : "Select a decision."}
            </p>
          ) : (
            <Detail
              dec={current} catalog={catalog} enrich={enrich} excluded={excluded} mode={mode} busy={busy}
              armedEnabled setMode={setMode}
              onToggleIp={(aid) => setExcluded((prev) => {
                const next = new Set(prev);
                if (next.has(aid)) next.delete(aid);
                else if (selectedPending(current).length > 1 || !current.actions.find((a) => a.id === aid && childPhase(a) === "pending")) next.add(aid);
                return next;
              })}
              onApprove={(armed) => approve(current, armed)}
              onReject={() => reject(current)}
              onRevert={() => revert(current)}
              onArmForReal={() => armForReal(current)}
            />
          )}
        </div>

        {/* ---- context rail ---- */}
        {attr && d && (
          <div className="iw-rail">
            <div className="iw-rail-head">WHY THIS INCIDENT</div>
            <div className="iw-tl">
              {d.timeline.slice(-6).map((e, i) => (
                <div className="iw-tlrow" key={i}>
                  <span className="iw-tltime mono">{clock(e.timestamp)}</span>
                  <span className="iw-tltext" title={`${e.actor ? `${e.actor} · ` : ""}${e.detail} · ${e.phase.replace(/_/g, " ")}`}>
                    <span className="iw-tldetail">{e.actor ? `${e.actor} · ` : ""}{e.detail}</span>
                    <span className="iw-phase" style={{ color: PHASE_COLOR[e.phase] ?? "var(--haze)" }}> · {e.phase.replace(/_/g, " ")}</span>
                  </span>
                </div>
              ))}
            </div>

            {attr.techniques.length > 0 && (
              <>
                <div className="iw-rail-head">MAPPED TECHNIQUES</div>
                <div className="iw-techs">
                  {attr.techniques.map((t) => (
                    <span className="iw-tech mono" key={t.id} title={t.description}>{t.id} · {t.name}</span>
                  ))}
                </div>
              </>
            )}

            {attr.predicted_next && (
              <div className="iw-next">
                <div className="iw-next-k mono">PREDICTED NEXT</div>
                <div className="iw-next-t">
                  {phases.slice(-1)[0]?.replace(/_/g, " ")} → <b>{attr.predicted_next}</b> — the tactic to hunt for now.
                </div>
              </div>
            )}
            {attr.grounded && (
              <div className="iw-grounded"><Icon name="check" /> grounded — every technique cited from the retrieved ATT&amp;CK set</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ---- sub-components ----------------------------------------------------------
function Header({ entity, score, awaiting, utc, highConfidence }:
  { entity: string; score: number; awaiting: number; utc: string; highConfidence?: boolean }) {
  return (
    <div className="iw-bar">
      <Link href="/" className="iw-brand">
        <span className="deva">प्रहरी</span><span className="name">PRAHARI</span>
      </Link>
      <Link href="/" className="iw-cmdlink mono"><Icon name="chevron" dir="left" /> command view</Link>
      <span className="spacer" />
      <span className="iw-chip incident mono">{highConfidence ? "● " : ""}{entity} — ACTIVE · {score.toFixed(2)}</span>
      {awaiting > 0 && <span className="iw-chip await mono">{awaiting} AWAITING APPROVAL</span>}
      <ThemeToggle compact />
      <Link href="/settings" className="iw-chip nav mono" title="Settings"><Icon name="gear" /></Link>
      <span className="iw-chip clock mono">{utc} UTC</span>
    </div>
  );
}

function QueueRow({ dec, active, resolved = false, onClick }:
  { dec: Decision; active: boolean; resolved?: boolean; onClick: () => void }) {
  const outcome = ({ dry_done: "✓ approved · dry-run", live_done: "✓ executed · live", running: "· dispatched",
    rejected: "✕ rejected", reverted: "↩ reverted", failed: "✕ failed" } as Record<string, string>)[dec.status] ?? "";
  return (
    <button type="button" className={`iw-qrow${active ? " on" : ""}${resolved ? " resolved" : ""}`} onClick={onClick}>
      <div className="iw-qtop">
        <span className="iw-qdot" style={{ background: dec.dot }} />
        <span className="iw-qtitle">{dec.title}</span>
      </div>
      {resolved
        ? <div className={`iw-qoutcome${dec.status === "rejected" || dec.status === "reverted" ? " muted" : ""}`}>{outcome}</div>
        : <div className="iw-qsub">{dec.sub}</div>}
    </button>
  );
}

function Detail({ dec, catalog, enrich, excluded, mode, busy, armedEnabled, setMode,
  onToggleIp, onApprove, onReject, onRevert, onArmForReal }: {
    dec: Decision; catalog: Record<string, PlaybookInfo>; enrich: Record<string, NetworkDetail>;
    excluded: Set<string>; mode: "dry" | "armed"; busy: boolean; armedEnabled: boolean;
    setMode: (m: "dry" | "armed") => void; onToggleIp: (aid: string) => void;
    onApprove: (armed: boolean) => void; onReject: () => void; onRevert: () => void; onArmForReal: () => void;
  }) {
  const info = catalog[dec.playbook];
  const st = dec.status;
  const armed = mode === "armed" && !dec.readOnly;
  const isBlock = dec.playbook === "block_ip";
  const selCount = dec.actions.filter((a) => childPhase(a) === "pending" && !excluded.has(a.id)).length;

  const forensics = dec.actions.map((a) => a.result?.forensics).find(Boolean);

  // real command output collected from executed children
  const resultLines: string[] = [];
  for (const a of dec.actions) {
    const r = a.result;
    if (!r) continue;
    if (r.command) resultLines.push(`$ ${r.command}`);
    if (r.note) resultLines.push(r.note);
    if (r.stdout) resultLines.push(r.stdout);
    if (r.error) resultLines.push(`error: ${r.error}`);
  }
  const resultTag = dec.readOnly ? "READ-ONLY — evidence collected, host unchanged"
    : st === "dry_done" ? "DRY-RUN — this is what WOULD run; nothing changed on the host"
      : st === "reverted" ? "REVERTED — the rule was removed; host restored"
        : "LIVE — executed on host";

  return (
    <>
      <div className="iw-dhead">
        <span className="iw-dtitle">{dec.title}</span>
        {dec.reversible && !dec.readOnly && <span className="iw-badge rev">REVERSIBLE</span>}
        {dec.readOnly && <span className="iw-badge ro">READ-ONLY</span>}
        <span className="iw-badge tier" title={`Response ladder tier ${dec.tier}`}>
          T{dec.tier} · {TIER_LABEL[dec.tier] ?? "action"}
        </span>
        {dec.escalation && <span className="iw-badge esc">LAST RESORT</span>}
        <span className="spacer" />
        <span className="iw-dstatus mono" style={{ color: STATUS_META[st].color }}>{STATUS_META[st].label}</span>
      </div>

      {/* the system arguing against its own most destructive option */}
      {dec.escalation && dec.gateNote && (
        <div className="iw-whynot">
          <div className="iw-whynot-k mono">WHY THIS ISN&apos;T RECOMMENDED YET</div>
          <div className="iw-whynot-t">{dec.gateNote}</div>
        </div>
      )}

      <div className="iw-reason">{dec.reason}</div>

      {/* block: IP table */}
      {isBlock && (
        <div className="iw-iptable">
          <div className="iw-iphead mono"><span /><span>ADDRESS</span><span>ENRICHMENT</span><span className="r">FLOWS</span></div>
          {dec.actions.map((a) => {
            const e = enrich[a.target];
            const on = !excluded.has(a.id);
            const bad = e?.severity === "bad";
            const note = e
              ? (e.reputation.listed ? `on blocklist: ${e.reputation.sources.join(", ")}`
                : [e.provider, e.city, e.country].filter(Boolean).join(" · ") || e.label)
              : "resolving…";
            const flows = e ? `${e.flow_count} · ${fmtBytes(e.total_bytes)}` : "—";
            const locked = childPhase(a) !== "pending";
            return (
              <button type="button" key={a.id} className={`iw-iprow${on ? "" : " off"}`}
                disabled={locked} onClick={() => onToggleIp(a.id)}>
                <span className={`iw-ipbox${on ? " on" : ""}`}>{on ? <Icon name="check" /> : null}</span>
                <span className="iw-ip mono">{a.target}</span>
                <span className={`iw-ipnote${bad ? " bad" : ""}`}>{note}</span>
                <span className="iw-ipflows mono">{flows}</span>
              </button>
            );
          })}
        </div>
      )}

      {/* isolate / disable / kill: what + cost */}
      {info && !isBlock && !dec.readOnly && (
        <div className="iw-cards">
          <div className="iw-card">
            <div className="iw-card-k mono ok">IF YOU APPROVE</div>
            <div className="iw-card-t">{info.what}</div>
          </div>
          <div className="iw-card">
            <div className="iw-card-k mono bad">COST</div>
            <div className="iw-card-t">{info.impact}</div>
          </div>
        </div>
      )}

      {/* snapshot / read-only note */}
      {dec.readOnly && info && (
        <div className="iw-note">
          <div className="iw-card-k mono ok">SAFE ACTION</div>
          <div className="iw-card-t">{info.impact} Read-only actions have no arm step and run immediately when approved.</div>
        </div>
      )}

      {/* command preview (pending) — honest: describes what runs; exact command is reported on dry-run */}
      {st === "pending" && info && (
        <div className="iw-preview">
          <div className="iw-preview-k mono">{dec.readOnly ? "WILL COLLECT" : armed ? "ARMED — WILL EXECUTE ON HOST" : "DRY-RUN WILL REPORT THE EXACT COMMAND"}</div>
          <div className="iw-cmd mono">{info.what}</div>
        </div>
      )}

      {/* forensics: structured findings rather than a wall of ps aux */}
      {forensics && <ForensicsReport data={forensics} />}

      {/* result (executed / reverted) */}
      {!forensics && (resultLines.length > 0 || st === "reverted") && (
        <div className={`iw-result${st === "live_done" ? " live" : ""}`}>
          {resultLines.map((ln, i) => <div className="iw-cmd mono" key={i}>{ln}</div>)}
          <div className="iw-result-tag mono">{resultTag}</div>
        </div>
      )}

      <div className="iw-spacer" />

      {/* footer */}
      <div className="iw-foot">
        {st === "pending" && (
          <>
            {!dec.readOnly && (
              <div className="iw-modes">
                <button type="button" className={`iw-mode${armed ? "" : " on"}`} onClick={() => setMode("dry")}>Dry-run</button>
                <button type="button" className={`iw-mode${armed ? " on" : ""}`} onClick={() => setMode("armed")} disabled={!armedEnabled}>
                  Armed <Icon name="warn" />
                </button>
              </div>
            )}
            <button type="button" className={`iw-approve${armed ? " armed" : ""}`} disabled={busy || selCount === 0}
              onClick={() => onApprove(armed)}>
              {dec.readOnly ? "Approve · run" : isBlock ? `Approve ${selCount} of ${dec.actions.length} · ${armed ? "armed" : "dry-run"}` : `Approve · ${armed ? "armed" : "dry-run"}`}
              {armed && !dec.readOnly ? <Icon name="warn" /> : <Icon name="chevron" />}
            </button>
            <button type="button" className="iw-reject" disabled={busy} onClick={onReject}>
              {isBlock ? "Reject all" : "Reject"}
            </button>
          </>
        )}
        {st === "running" && <span className="iw-foot-note mono">dispatched · waiting for the agent on {dec.actions[0]?.host}…</span>}
        {st === "dry_done" && (
          <>
            <button type="button" className="iw-arm-now" disabled={busy} onClick={onArmForReal}>Arm &amp; approve for real <Icon name="warn" /></button>
            <span className="iw-foot-note">dry-run verified — the host is unchanged</span>
          </>
        )}
        {st === "live_done" && (
          <>
            {dec.reversible && <button type="button" className="iw-revert" disabled={busy} onClick={onRevert}>Revert <Icon name="undo" /></button>}
            <span className="iw-foot-note">executed on host · approver: operator</span>
          </>
        )}
        {st === "failed" && <span className="iw-foot-note" style={{ color: "var(--alert)" }}>action failed — see output above</span>}
        {st === "rejected" && <span className="iw-foot-note">rejected — no change was made to the host</span>}
        {st === "reverted" && <span className="iw-foot-note">reverted — the original rule was removed from the host</span>}
        <span className="spacer" />
        <span className="iw-foot-note mono">approver: operator</span>
      </div>
    </>
  );
}

// ---- forensics report -------------------------------------------------------
/** Renders the snapshot as findings an analyst can act on, not a terminal dump.
 *  The headline is always the pivot: which process owns the incident's C2 socket. */
function ForensicsReport({ data }: { data: Forensics }) {
  const [raw, setRaw] = useState(false);
  const attributed = data.connections.filter((c) => c.pid);

  return (
    <div className="iw-fx">
      <div className="iw-fx-head">
        <span className="iw-fx-title">Forensic findings</span>
        <span className={`iw-badge ${data.root ? "ro" : "esc"}`}>{data.root ? "ROOT" : "DEGRADED"}</span>
        <span className="spacer" />
        <span className="iw-fx-meta mono">
          {data.counts.ioc_matches} IOC match{data.counts.ioc_matches === 1 ? "" : "es"} ·{" "}
          {data.counts.shown}/{data.counts.sockets} sockets
        </span>
      </div>

      {data.degraded.map((d, i) => <div className="iw-fx-warn" key={i}>{d}</div>)}

      {data.findings.length === 0 ? (
        <div className="iw-fx-empty mono">
          No process could be tied to this incident&apos;s addresses — the channel may already be closed.
        </div>
      ) : data.findings.map((f, i) => (
        <div className={`iw-fx-find ${f.severity}`} key={i}>
          <div className="iw-fx-ftitle">{f.title}</div>
          <div className="iw-fx-fdetail">{f.detail}</div>
          {f.sha256 && <div className="iw-fx-hash mono" title={f.sha256}>sha256 {f.sha256.slice(0, 32)}…</div>}
        </div>
      ))}

      {attributed.length > 0 && (
        <>
          <div className="iw-fx-sub mono">ATTRIBUTED SOCKETS</div>
          <div className="iw-fx-tbl">
            {attributed.slice(0, 8).map((c, i) => (
              <div className="iw-fx-row" key={i}>
                <span className="a mono">{c.addr}</span>
                <span className="b mono">{c.state.toLowerCase()}</span>
                <span className="c mono">pid {c.pid}</span>
                <span className="d" title={c.exe ?? ""}>{c.exe ?? c.cmdline ?? "—"}</span>
                <span className="e mono">{c.user ?? "—"}</span>
              </div>
            ))}
          </div>
          {/* the parent chain is the 'how did they get in' answer */}
          {attributed.filter((c) => c.parents?.length).slice(0, 2).map((c, i) => (
            <div className="iw-fx-chain mono" key={i}>
              <span className="k">pid {c.pid} launched by</span>{" "}
              {c.parents!.map((p) => p.cmdline.split(" ")[0] || p.exe).join(" ← ")}
            </div>
          ))}
        </>
      )}

      {data.persistence.length > 0 && (
        <>
          <div className="iw-fx-sub mono">PERSISTENCE TOUCHED IN THE LAST 24H</div>
          {data.persistence.slice(0, 6).map((p, i) => (
            <div className="iw-fx-row persist" key={i}>
              <span className="d mono" title={p.path}>{p.path}</span>
              <span className="e mono">{p.kind}</span>
            </div>
          ))}
        </>
      )}

      <button type="button" className="iw-fx-toggle mono" onClick={() => setRaw((v) => !v)}>
        {raw ? "hide" : "show"} raw collection
      </button>
      {raw && <pre className="iw-fx-raw mono">{JSON.stringify(data, null, 2)}</pre>}
      <div className="iw-result-tag mono">READ-ONLY — evidence collected, host unchanged</div>
    </div>
  );
}
