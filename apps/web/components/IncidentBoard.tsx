import Link from "next/link";

import type { IncidentSummary } from "../lib/api";
import { age, clock, shortSource } from "../lib/format";

function Row({ i, attributed, now }: { i: IncidentSummary; attributed: boolean; now: number | null }) {
  const started = age(i.start, now);
  return (
    <Link
      href={`/incidents/${i.id}`}
      className={`inc-row${i.is_true_positive ? " tp" : i.high_confidence ? " hi" : ""}`}
    >
      <div className="entity">
        <span className="lbl">ENTITY</span>
        {i.entity}
      </div>
      <div className="body">
        <div className="meta">
          {i.high_confidence
            ? <span className="pill hi">● HIGH-CONFIDENCE</span>
            : <span className="pill calm">WATCH</span>}
          {i.is_true_positive && <span className="pill rt">RED-TEAM CONFIRMED</span>}
          {attributed && <span className="pill attr">ATT&amp;CK MAPPED</span>}
          <span className="chain mono">
            {i.phases.map((p, idx) => (
              <span key={p}>
                {idx > 0 && <span className="dim"> ▸ </span>}
                <span className={`ph ${p}`}>{p.replace(/_/g, " ")}</span>
              </span>
            ))}
          </span>
        </div>
        <div className="facts mono">
          <b>{i.event_count}</b> events · <b>{i.source_count}</b> sensors
          {i.sources.length > 0 && (
            <span className="srcline">
              {" "}[{i.sources.map(shortSource).join(" · ")}]
            </span>
          )}
          {" "}· first seen <b>{clock(i.start)}</b>
          {started ? <span className="dim"> · {started}</span> : ""}
        </div>
        <div className="meter" aria-hidden>
          <span style={{ width: `${Math.round(i.compound_score * 100)}%` }} />
        </div>
      </div>
      <div className="score">
        <div className="v mono">{i.compound_score.toFixed(2)}</div>
        <div className="c">COMPOUND</div>
      </div>
    </Link>
  );
}

const EMPTY = new Set<string>();

export function IncidentBoard({
  incidents, variant, attributed = EMPTY, now = null, filter = "all", onClearFilter, flash = false,
}: {
  incidents: IncidentSummary[];
  variant: "live" | "demo";
  attributed?: Set<string>;
  now?: number | null;
  filter?: "all" | "high";
  onClearFilter?: () => void;
  flash?: boolean;
}) {
  const shown = filter === "high" ? incidents.filter((i) => i.high_confidence) : incidents;
  return (
    <section className={`panel incpanel${flash ? " flash" : ""}`} id="incidents">
      <h2>
        Active incidents <span className="hint">— ranked by compound risk</span>
        <span className="spacer" />
        {filter === "high" && (
          <button type="button" className="pill hi clearable" onClick={onClearFilter}>
            HIGH-CONFIDENCE ONLY ✕
          </button>
        )}
        {variant === "demo"
          ? <span className="pill demo">SCENARIO REPLAY</span>
          : incidents.length > 0 && <span className="pill livepill">LIVE CORRELATION</span>}
      </h2>
      {shown.length === 0 ? (
        <div className="empty">
          <p className="mono dim">
            {filter === "high" && incidents.length > 0
              ? "no high-confidence incidents — clear the filter to see watch-level ones"
              : "no incidents — correlation quiet, monitoring live telemetry"}
          </p>
        </div>
      ) : (
        <div className="inc-list">
          {shown.map((i) => (
            <Row key={i.id} i={i} attributed={attributed.has(i.id)} now={now} />
          ))}
        </div>
      )}
    </section>
  );
}
