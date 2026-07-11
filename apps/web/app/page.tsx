import { CommandDeck } from "../components/CommandDeck";
import {
  getIncidents, getMetrics, getRecentEvents, getStatus,
  type IncidentSummary, type Metrics, type Status, type TapeEvent,
} from "../lib/api";

export const dynamic = "force-dynamic";

async function safe<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p;
  } catch {
    return null;
  }
}

export default async function CommandView() {
  const [incidents, metrics, status, tape] = await Promise.all([
    safe<IncidentSummary[]>(getIncidents()),
    safe<Metrics>(getMetrics()),
    safe<Status>(getStatus()),
    safe<TapeEvent[]>(getRecentEvents()),
  ]);

  return (
    <main className="wrap">
      <CommandDeck
        initialIncidents={incidents ?? []}
        initialStatus={status}
        initialTape={tape ?? []}
        metrics={metrics}
      />
    </main>
  );
}
