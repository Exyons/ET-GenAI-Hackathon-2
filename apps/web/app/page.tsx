import Link from "next/link";

import { TopBar } from "../components/TopBar";
import { getIncidents, getMetrics, type IncidentSummary, type Metrics } from "../lib/api";

export const dynamic = "force-dynamic";

function ProofStrip({ m }: { m: Metrics }) {
  return (
    <div className="proof">
      <div className="stat">
        <div className="n good">{m.behavioural_recall.toFixed(2)}</div>
        <div className="l">Behavioural recall</div>
        <div className="s">real LANL red-team</div>
      </div>
      <div className="stat">
        <div className="n bad">{m.signature_recall.toFixed(2)}</div>
        <div className="l">Signature recall</div>
        <div className="s">blind to valid-cred moves</div>
      </div>
      <div className="stat">
        <div className="n amp">{m.mttd_seconds}s</div>
        <div className="l">MTTD</div>
        <div className="s">industry baseline: weeks</div>
      </div>
      <div className="stat">
        <div className="n amp">{m.attack_techniques}</div>
        <div className="l">ATT&amp;CK techniques</div>
        <div className="s">local · air-gapped RAG</div>
      </div>
    </div>
  );
}

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

function Offline({ error }: { error: string }) {
  return (
    <div className="panel" style={{ marginTop: 24 }}>
      <div className="pad">
        <div className="eyebrow">Backend offline</div>
        <p style={{ color: "var(--haze)", fontSize: 13.5, lineHeight: 1.6 }}>
          Start the API to load incidents:<br />
          <span className="mono">cd apps/api &amp;&amp; uv run uvicorn prahari.main:app --port 8000</span>
        </p>
        <div className="mono" style={{ color: "var(--phosphor-dim)", fontSize: 11 }}>{error}</div>
      </div>
    </div>
  );
}

export default async function CommandView() {
  let incidents: IncidentSummary[] = [];
  let metrics: Metrics | null = null;
  let error = "";
  try {
    [incidents, metrics] = await Promise.all([getIncidents(), getMetrics()]);
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return (
    <main className="wrap">
      <TopBar />
      <div className="h-sec">Detection proof — behavioural vs signature</div>
      {metrics ? <ProofStrip m={metrics} /> : <Offline error={error} />}

      <div className="h-sec">Active incidents · ranked by compound risk</div>
      {incidents.length > 0 ? (
        <div className="inc-list">
          {incidents.map((i) => <IncidentRow key={i.id} i={i} />)}
        </div>
      ) : (
        !error && <p style={{ color: "var(--haze)" }}>No active incidents.</p>
      )}
    </main>
  );
}
