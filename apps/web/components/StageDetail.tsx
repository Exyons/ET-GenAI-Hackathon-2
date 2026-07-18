"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import {
  getActions, getIncidents, getStatus, PLAYBOOK_TITLE,
  type IncidentSummary, type ResponseAction, type Status,
} from "../lib/api";
import { clock, shortSource } from "../lib/format";
import { STAGE_BY_SLUG, type StageSlug } from "../lib/pipeline";
import { Icon } from "./Icon";
import { TopBar } from "./TopBar";

function lastSeen(s: number | null): string {
  if (s === null) return "never";
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function Fact({ k, v, tone }: { k: string; v: React.ReactNode; tone?: "ok" | "warn" | "bad" }) {
  return <div className="fact"><div className="k">{k}</div><div className={`v${tone ? ` ${tone}` : ""}`}>{v}</div></div>;
}

const REASON_COLORS: Record<string, string> = {
  auth_anomaly: "var(--s-auth)", net_anomaly: "var(--s-net)", discovery: "var(--violet)",
  process_corroborated: "var(--phosphor)", external_corroborated: "#d95926",
};

function CollectBody({ status }: { status: Status | null }) {
  const hosts = status?.fleet?.hosts ?? [];
  return (
    <div className="stage-section">
      <h2>Sensor fleet</h2>
      {hosts.length === 0 ? <p className="stage-note">No agents reporting.</p> : (
        <div className="stagelog"><table className="fleet-table">
          <thead><tr><th>Host</th><th>OS</th><th>Sources</th><th>Ev/min</th><th>Total</th><th>Last seen</th></tr></thead>
          <tbody>
            {hosts.map((h) => (
              <tr key={h.host}>
                <td className="mono">{h.host}</td>
                <td>{h.os}</td>
                <td className="mono">{(h.agent ? Object.entries(h.agent).map(([n, s]) =>
                  s.state === "error" ? `${n}✕` : `${n} ${s.n}`) : h.sources.map(shortSource)).join(" · ")}</td>
                <td className="mono">{h.epm}</td>
                <td className="mono">{h.total}</td>
                <td className="mono">{lastSeen(h.last_seen_s)}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}
      <p className="stage-note">Agents dial out to Prahari and poll for approved actions — no inbound ports are opened on monitored hosts.</p>
    </div>
  );
}

function IngestBody({ status }: { status: Status | null }) {
  const p = status?.pipeline; const st = p?.stats ?? {}; const d = p?.detectors;
  const warmup = status?.mode === "warmup";
  return (
    <div className="stage-section">
      <h2>Baseline</h2>
      <div className="stage-facts">
        <Fact k="Mode" v={warmup ? "Warmup — learning" : "Frozen"} tone={warmup ? "warn" : "ok"} />
        <Fact k="Warmup window" v={`${status?.warmup_seconds ?? "—"}s`} />
        <Fact k="Auth model" v={d?.auth ? "fit" : "off (too few events)"} tone={d?.auth ? "ok" : undefined} />
        <Fact k="Network model" v={d?.network ? "fit" : "off (too few events)"} tone={d?.network ? "ok" : undefined} />
        <Fact k="Known-normal commands" v={p?.process_baseline_size ?? 0} />
        <Fact k="Events screened out" v={st.screened ?? 0} />
        <Fact k="Batches / events" v={`${st.batches ?? 0} / ${st.events ?? 0}`} />
      </div>
      <p className="stage-note">Suspicious events (discovery, failed auth, external flows) are screened out of the fit so the baseline can't be poisoned. It is persisted and reloaded on restart — re-learning only via an operator baseline reset.</p>
    </div>
  );
}

function DetectBody({ status }: { status: Status | null }) {
  const st = status?.pipeline?.stats ?? {};
  const reasons: [string, number][] = [
    ["auth_anomaly", st.auth_anomaly ?? 0], ["net_anomaly", st.net_anomaly ?? 0],
    ["discovery", st.discovery ?? 0], ["process_corroborated", st.process_corroborated ?? 0],
    ["external_corroborated", st.external_corroborated ?? 0],
  ];
  const max = Math.max(1, ...reasons.map(([, n]) => n));
  return (
    <div className="stage-section">
      <h2>Why events were flagged</h2>
      <div className="reasonbars">
        {reasons.map(([k, n]) => (
          <div key={k} className="rbar">
            <span className="rk">{k.replace(/_/g, " ")}</span>
            <span className="rtrack"><span className="rfill" style={{ width: `${(n / max) * 100}%`, background: REASON_COLORS[k] }} /></span>
            <span className="rn">{n}</span>
          </div>
        ))}
      </div>
      <p className="stage-note">Sentinels compare each event strictly above the learned threshold, so a homogeneous baseline never flags ordinary traffic. A flagged process only corroborates when the host already shows auth or network anomalies — one recon command can't cascade into flagging everything.</p>
    </div>
  );
}

function CorrelateBody({ incidents }: { incidents: IncidentSummary[] }) {
  return (
    <div className="stage-section">
      <h2>Open incidents ({incidents.length})</h2>
      {incidents.length === 0 ? <p className="stage-note">Correlation quiet — no open incidents.</p> : (
        <div className="stagelog"><table className="fleet-table">
          <thead><tr><th>Entity</th><th>Compound</th><th>Confidence</th><th>Sensors</th><th>Phases</th><th></th></tr></thead>
          <tbody>
            {incidents.map((i) => (
              <tr key={i.id}>
                <td className="mono">{i.entity}</td>
                <td className="mono">{i.compound_score.toFixed(2)}</td>
                <td>{i.high_confidence ? "high-confidence" : "watch"}</td>
                <td className="mono">{i.source_count}</td>
                <td className="mono">{i.phase_count}</td>
                <td><Link href={`/incidents/${i.id}`} className="mono" style={{ color: "var(--phosphor-dim)" }}>open ▸</Link></td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}
    </div>
  );
}

function AttributeBody({ status }: { status: Status | null }) {
  const p = status?.pipeline; const st = p?.stats ?? {};
  return (
    <div className="stage-section">
      <h2>Attribution engine</h2>
      <div className="stage-facts">
        <Fact k="Chat model" v={p?.models.chat ?? "—"} />
        <Fact k="Embedding model" v={p?.models.embed ?? "—"} />
        <Fact k="Incidents mapped" v={st.attributed ?? 0} tone="ok" />
        <Fact k="Attribution failures" v={st.attribution_failed ?? 0} tone={(st.attribution_failed ?? 0) > 0 ? "bad" : undefined} />
      </div>
      {p?.attribution_error && <p className="stage-note" style={{ borderLeftColor: "var(--alert)", color: "var(--alert)" }}><Icon name="warn" /> {p.attribution_error} — retrying every 60s.</p>}
      <p className="stage-note">Every technique is retrieved from the ATT&CK corpus before the model answers, and IDs outside the retrieved set are dropped — so attributions are grounded, not hallucinated. Both models run locally; nothing leaves the box.</p>
    </div>
  );
}

function RespondBody({ actions }: { actions: ResponseAction[] }) {
  return (
    <div className="stage-section">
      <h2>Response actions ({actions.length})</h2>
      {actions.length === 0 ? <p className="stage-note">No response actions recommended yet.</p> : (
        <div className="stagelog"><table className="fleet-table">
          <thead><tr><th>Playbook</th><th>Target</th><th>Status</th><th>Mode</th><th>Incident</th></tr></thead>
          <tbody>
            {actions.map((a) => (
              <tr key={a.id}>
                <td>{PLAYBOOK_TITLE[a.playbook] ?? a.playbook}{a.undo ? " (revert)" : ""}</td>
                <td className="mono">{a.target}</td>
                <td>{a.status.replace(/_/g, " ")}{a.result ? (a.result.dry_run ? " · dry-run" : " · live") : ""}</td>
                <td>{a.mode}</td>
                <td><Link href={`/incidents/${a.incident_id}`} className="mono" style={{ color: "var(--phosphor-dim)" }}>{a.incident_id}</Link></td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}
      <p className="stage-note">Triple gate: an operator approves, approves it armed (default is dry-run), and the agent was started with armed execution enabled. Read-only snapshots always run; reversible actions can be reverted.</p>
    </div>
  );
}

export function StageDetail({ slug }: { slug: StageSlug }) {
  const stage = STAGE_BY_SLUG[slug];
  const [status, setStatus] = useState<Status | null>(null);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [actions, setActions] = useState<ResponseAction[]>([]);

  useEffect(() => {
    const load = () => {
      getStatus().then(setStatus).catch(() => {});
      getIncidents().then(setIncidents).catch(() => {});
      getActions().then(setActions).catch(() => {});
    };
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, []);

  const st = stage.state(status);
  const activity = (status?.pipeline?.activity ?? []).filter((a) => a.stage === stage.activityStage).reverse();

  return (
    <>
      <TopBar />
      <div className="stagepage">
        <div className="crumbs mono">
          <Link href="/">command view</Link> / pipeline / <b>{stage.word}</b>
        </div>
        <header className={`stage-hero ${stage.cls}`}>
          <div>
            <div className="eyebrow">PIPELINE STAGE</div>
            <h1>{stage.name}</h1>
            <p>{stage.about}</p>
          </div>
          <span className={`stage-state big mono${st.tone ? ` ${st.tone}` : ""}`}>{st.label}</span>
        </header>

        <div className="stage-tiles">
          {stage.lines(status).map(([k, v]) => (
            <div key={k} className="stage-tile"><div className="l">{k}</div><div className="v mono">{v}</div></div>
          ))}
        </div>

        {slug === "collect" && <CollectBody status={status} />}
        {slug === "ingest" && <IngestBody status={status} />}
        {slug === "detect" && <DetectBody status={status} />}
        {slug === "correlate" && <CorrelateBody incidents={incidents} />}
        {slug === "attribute" && <AttributeBody status={status} />}
        {slug === "respond" && <RespondBody actions={actions} />}

        {stage.activityStage && (
          <div className="stage-section">
            <h2>Activity log · {stage.word}</h2>
            {activity.length === 0 ? <p className="stage-note">No activity from this stage yet.</p> : (
              <div className="stagelog">
                {activity.map((a, i) => (
                  <div key={`${a.t}-${i}`} className="logline mono">
                    <span className="t">{clock(a.t)}</span><span className="m">{a.msg}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
      <Link href="/" className="back">◂ back to command view</Link>
    </>
  );
}
