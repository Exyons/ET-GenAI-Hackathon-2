import Link from "next/link";

import { PrintButton } from "../../components/PrintButton";
import { SummaryReport } from "../../components/SummaryReport";
import {
  getActions, getIncident, getIncidents, getMetrics, getStatus,
  PLAYBOOK_TITLE,
  type IncidentDetail, type IncidentSummary, type Metrics, type ResponseAction,
  type Status,
} from "../../lib/api";
import { clock, shortSource } from "../../lib/format";

export const dynamic = "force-dynamic";

const PHASE_LABEL: Record<string, string> = {
  lateral_movement: "Lateral movement",
  discovery: "Discovery",
  execution: "Execution",
  command_and_control: "Command & control",
};

async function safe<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p;
  } catch {
    return null;
  }
}

function trunc(s: string, max = 160): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

export default async function ReportPage() {
  const [status, incidents, metrics, actions] = await Promise.all([
    safe<Status>(getStatus()),
    safe<IncidentSummary[]>(getIncidents()),
    safe<Metrics>(getMetrics()),
    safe<ResponseAction[]>(getActions()),
  ]);
  const details: IncidentDetail[] = [];
  for (const i of (incidents ?? []).slice(0, 8)) {
    const d = await safe<IncidentDetail>(getIncident(i.id));
    if (d) details.push(d);
  }

  const generated = new Date().toISOString().replace("T", " ").slice(0, 19);
  const fleet = status?.fleet;

  if (!status) {
    return (
      <main className="wrap">
        <p className="mono" style={{ marginTop: 28 }}>Report unavailable — API offline.</p>
        <Link href="/" className="back">◂ back to command view</Link>
      </main>
    );
  }

  return (
    <main className="report-wrap">
      <div className="report-actions no-print">
        <Link href="/" className="back">◂ back to command view</Link>
        <PrintButton />
      </div>

      <article className="report">
        <header>
          <h1>PRAHARI · Situation report</h1>
          <p className="meta">Generated {generated} UTC · mode: {status.mode.toUpperCase()}
            {status.baseline_ready ? " · baseline frozen" : ""} · sovereign / air-gapped</p>
        </header>

        <SummaryReport />

        <section>
          <h2>2 · Sensor fleet ({fleet?.hosts.length ?? 0} hosts)</h2>
          <table>
            <thead>
              <tr><th>Host</th><th>OS</th><th>Source status</th><th>Events</th><th>Rate/min</th><th>Last seen</th></tr>
            </thead>
            <tbody>
              {(fleet?.hosts ?? []).map((h) => (
                <tr key={h.host}>
                  <td className="mono">{h.host}</td>
                  <td>{h.os}</td>
                  <td>{h.agent
                    ? Object.entries(h.agent).map(([n, s]) =>
                        `${n}: ${s.state === "error" ? `ERROR (${s.detail})` : `${s.state}, ${s.n} events`}`).join(" · ")
                    : h.sources.map(shortSource).join(" · ")}</td>
                  <td>{h.total}</td>
                  <td>{h.epm}</td>
                  <td>{h.last_seen_s != null ? `${Math.round(h.last_seen_s)}s ago` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <section>
          <h2>3 · Live incidents ({incidents?.length ?? 0})</h2>
          {details.length === 0 && <p className="quiet-note">No live correlated incidents — correlation quiet.</p>}
          {details.map((d) => (
            <div className="inc" key={d.summary.id}>
              <h3>
                {d.summary.entity} — compound {d.summary.compound_score.toFixed(2)}
                {d.summary.high_confidence ? " · HIGH-CONFIDENCE" : " · watch"}
                {d.summary.is_true_positive ? " · red-team confirmed" : ""}
              </h3>
              <p className="meta">
                {d.summary.event_count} events · {d.summary.source_count} sensors
                [{d.summary.sources.map(shortSource).join(" · ")}] ·
                phases: {d.summary.phases.map((p) => PHASE_LABEL[p] ?? p).join(" → ")} ·
                first seen {clock(d.summary.start)} UTC
              </p>
              <table>
                <colgroup>
                  <col className="c-time" /><col className="c-src" /><col className="c-actor" />
                  <col /><col className="c-phase" />
                </colgroup>
                <thead><tr><th>Time</th><th>Source</th><th>Actor</th><th>Event</th><th>Phase</th></tr></thead>
                <tbody>
                  {d.timeline.slice(0, 40).map((e, i) => (
                    <tr key={i}>
                      <td className="mono">{clock(e.timestamp)}</td>
                      <td>{shortSource(e.source)}</td>
                      <td className="mono">{e.actor ?? "—"}</td>
                      <td>{trunc(e.detail)}</td>
                      <td>{PHASE_LABEL[e.phase] ?? e.phase}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {d.timeline.length > 40 && (
                <p className="meta">…{d.timeline.length - 40} earlier events omitted.</p>
              )}
              {d.attribution.techniques.length > 0 && (
                <p className="attr">
                  <b>ATT&amp;CK:</b> {d.attribution.techniques.map((t) => `${t.id} ${t.name} (${t.tactic})`).join(" · ")}
                  {d.attribution.predicted_next ? ` — predicted next: ${d.attribution.predicted_next}` : ""}
                  {d.attribution.explanation ? <><br />{d.attribution.explanation}</> : null}
                </p>
              )}
            </div>
          ))}
        </section>

        <section>
          <h2>4 · Response actions ({actions?.length ?? 0})</h2>
          {(actions?.length ?? 0) === 0 ? (
            <p className="quiet-note">No response actions recommended.</p>
          ) : (
            <table>
              <colgroup>
                <col className="c-time" /><col /><col /><col className="c-host" />
                <col className="c-phase" /><col className="c-phase" />
              </colgroup>
              <thead><tr><th>Time</th><th>Playbook</th><th>Target</th><th>Status</th><th>Mode</th><th>Approver</th></tr></thead>
              <tbody>
                {(actions ?? []).map((a) => (
                  <tr key={a.id}>
                    <td className="mono">{clock(a.created_at)}</td>
                    <td>{PLAYBOOK_TITLE[a.playbook] ?? a.playbook}{a.undo ? " (revert)" : ""}</td>
                    <td className="mono">{a.target}</td>
                    <td>{a.status.replace(/_/g, " ")}{a.result ? (a.result.dry_run ? " · dry-run" : " · live") : ""}</td>
                    <td>{a.mode}</td>
                    <td className="mono">{a.approver ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        {metrics && (
          <footer>
            Recorded LANL red-team benchmark: behavioural recall {metrics.behavioural_recall.toFixed(2)} ·
            signature recall {metrics.signature_recall.toFixed(2)} · MTTD {metrics.mttd_seconds}s ·
            FP rate {(metrics.false_positive_rate * 100).toFixed(1)}% · {metrics.attack_techniques} ATT&amp;CK
            techniques via air-gapped RAG.
          </footer>
        )}
      </article>
    </main>
  );
}
