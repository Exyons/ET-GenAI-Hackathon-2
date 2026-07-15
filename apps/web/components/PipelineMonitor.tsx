import type { Status } from "../lib/api";
import { clock, compact } from "../lib/format";

const STAGE_CLS: Record<string, string> = {
  baseline: "st-base",
  sentinel: "st-sent",
  correlator: "st-corr",
  attribution: "st-attr",
  responder: "st-resp",
};

function Stage({ name, state, tone, lines, error }: {
  name: string; state?: string; tone?: "err" | "warn"; lines: [string, string][]; error?: string | null;
}) {
  return (
    <div className="stage">
      <div className="stage-head">
        <span className="stage-name">{name}</span>
        {state && <span className={`stage-state mono${tone ? ` ${tone}` : ""}`}>{state}</span>}
      </div>
      {lines.map(([k, v]) => (
        <div key={k} className="stage-line mono"><span className="k">{k}</span><span className="v">{v}</span></div>
      ))}
      {error && <div className="stage-err mono" title={error}>{error}</div>}
      <span className="stage-arrow" aria-hidden>▸</span>
    </div>
  );
}

export function PipelineMonitor({ status }: { status: Status | null }) {
  const p = status?.pipeline;
  const s = p?.stats ?? {};
  const resp = status?.response;
  const fleet = status?.fleet;
  const agents = fleet?.hosts ?? [];
  const tailing = agents.reduce((n, h) =>
    n + Object.values(h.agent ?? {}).filter((x) => x.state === "tailing").length, 0);
  const srcErrors = agents.reduce((n, h) =>
    n + Object.values(h.agent ?? {}).filter((x) => x.state === "error").length, 0);
  const warmup = status?.mode === "warmup";
  const anomalies = (s.auth_anomaly ?? 0) + (s.net_anomaly ?? 0);
  const heuristics = (s.discovery ?? 0) + (s.process_corroborated ?? 0) + (s.external_corroborated ?? 0);

  return (
    <section className="panel pipemon">
      <h2>
        Pipeline <span className="hint">— collect → screen → detect → correlate → attribute → respond</span>
        <span className="spacer" />
        <span className="hint mono">live · updates every 2s</span>
      </h2>
      <div className="stages">
        <Stage name="Collect" state={agents.length > 0 ? "ACTIVE" : "IDLE"} lines={[
          ["agents", String(agents.length)],
          ["sources tailing", srcErrors > 0 ? `${tailing} · ${srcErrors} error` : String(tailing)],
          ["ev/min", String(fleet?.rate_epm ?? 0)],
        ]} />
        <Stage name="Ingest · screen" state={warmup ? "LEARNING" : "FROZEN"} lines={[
          ["batches", compact(s.batches ?? 0)],
          ["events", compact(s.events ?? 0)],
          ["screened out", String(s.screened ?? 0)],
        ]} />
        <Stage name="Detect · sentinels"
          state={p ? `${(p.detectors.auth ? 1 : 0) + (p.detectors.network ? 1 : 0)}/2 models` : "—"} lines={[
          ["ML anomalies", `${anomalies} (auth ${s.auth_anomaly ?? 0} · net ${s.net_anomaly ?? 0})`],
          ["heuristics", `${heuristics} (disc ${s.discovery ?? 0} · corr ${(s.process_corroborated ?? 0) + (s.external_corroborated ?? 0)})`],
          ["known-normal cmds", String(p?.process_baseline_size ?? 0)],
        ]} />
        <Stage name="Correlate" state={`${p?.window_seconds ?? "—"}s window`} lines={[
          ["flagged in window", String(status?.flagged_recent ?? 0)],
          ["open incidents", String(status?.incident_count ?? 0)],
          ["high-confidence", String(status?.high_confidence_count ?? 0)],
        ]} />
        <Stage name="Attribute · LLM"
          state={p?.attribution_error ? "ERROR" : "READY"}
          tone={p?.attribution_error ? "err" : undefined}
          error={p?.attribution_error}
          lines={[
            ["chat / embed", p ? `${p.models.chat} · ${p.models.embed}` : "—"],
            ["ATT&CK mapped", String(s.attributed ?? 0)],
            ["failed", String(s.attribution_failed ?? 0)],
          ]} />
        <Stage name="Respond · gate"
          state={(resp?.pending ?? 0) > 0 ? `${resp?.pending} PENDING` : "READY"}
          tone={(resp?.pending ?? 0) > 0 ? "warn" : undefined}
          lines={[
            ["recommended", String(resp?.total ?? 0)],
            ["awaiting approval", String(resp?.pending ?? 0)],
            ["executed / reverted", `${resp?.executed ?? 0} / ${resp?.reverted ?? 0}`],
          ]} />
      </div>
      <div className="pipelog">
        {(p?.activity ?? []).length === 0 ? (
          <div className="stage-line mono dim" style={{ padding: "8px 16px" }}>no pipeline activity yet</div>
        ) : (
          [...(p?.activity ?? [])].reverse().slice(0, 9).map((a, i) => (
            <div key={`${a.t}-${i}`} className="logline mono">
              <span className="t">{clock(a.t)}</span>
              <span className={`stagechip ${STAGE_CLS[a.stage] ?? ""}`}>{a.stage.toUpperCase()}</span>
              <span className="m">{a.msg}</span>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
