const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

export type IncidentSummary = {
  id: string;
  entity: string;
  compound_score: number;
  high_confidence: boolean;
  is_true_positive: boolean;
  phase_count: number;
  source_count: number;
  event_count: number;
  start: string;
};

export type EventView = {
  timestamp: string;
  event_type: string;
  phase: string;
  source: string;
  actor: string | null;
  detail: string;
};

export type TechniqueView = { id: string; name: string; tactic: string };

export type AttributionView = {
  technique_ids: string[];
  techniques: TechniqueView[];
  explanation: string;
  grounded: boolean;
  predicted_next: string;
};

export type IncidentDetail = {
  summary: IncidentSummary;
  timeline: EventView[];
  attribution: AttributionView;
};

export type Metrics = {
  behavioural_recall: number;
  signature_recall: number;
  mttd_seconds: number;
  attack_techniques: number;
  false_positive_rate: number;
};

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

export const getMetrics = () => get<Metrics>("/api/metrics");
export const getIncidents = () => get<IncidentSummary[]>("/api/incidents");
export const getIncident = (id: string) => get<IncidentDetail>(`/api/incidents/${id}`);
