import Link from "next/link";

import { Benchmark } from "../../components/Benchmark";
import { IncidentBoard } from "../../components/IncidentBoard";
import { TopBar } from "../../components/TopBar";
import { getDemoIncidents, getMetrics, type IncidentSummary, type Metrics } from "../../lib/api";

export const dynamic = "force-dynamic";

async function safe<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p;
  } catch {
    return null;
  }
}

export default async function DemoPage() {
  const [incidents, metrics] = await Promise.all([
    safe<IncidentSummary[]>(getDemoIncidents()),
    safe<Metrics>(getMetrics()),
  ]);

  return (
    <main className="wrap">
      <TopBar />
      <p className="demolead">
        Canned <b>LANL red-team scenario</b> — the fused C553 lateral-movement story used for
        walkthroughs, plus recorded benchmark numbers. The command view at{" "}
        <Link href="/" className="amp">/</Link> shows only live correlated incidents.
      </p>
      {incidents && incidents.length > 0 ? (
        <IncidentBoard incidents={incidents} variant="demo" />
      ) : (
        <div className="panel"><div className="empty">
          <p className="mono dim">scenario unavailable — is the API running?</p>
        </div></div>
      )}
      <Benchmark m={metrics} />
      <Link href="/" className="back">◂ back to command view</Link>
    </main>
  );
}
