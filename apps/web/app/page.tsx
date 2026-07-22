import { CommandMap } from "../components/CommandMap";
import {
  getIncidents, getRecentEvents, getStatus,
  type IncidentSummary, type Status, type TapeEvent,
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
  const [incidents, status, tape] = await Promise.all([
    safe<IncidentSummary[]>(getIncidents()),
    safe<Status>(getStatus()),
    safe<TapeEvent[]>(getRecentEvents()),
  ]);

  return (
    <CommandMap
      initialIncidents={incidents ?? []}
      initialStatus={status}
      initialTape={tape ?? []}
    />
  );
}
