export const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

export type EventType = "auth" | "process" | "network_flow";

export type AgentSourceStatus = {
  state: "starting" | "tailing" | "error" | string;
  detail: string;
  n: number;
};

export type FleetHost = {
  host: string;
  os: "linux" | "windows" | "unknown";
  sources: string[];
  by_type: Partial<Record<EventType, number>>;
  total: number;
  epm: number;
  last_seen_s: number | null;
  agent?: Record<string, AgentSourceStatus> | null;
};

export type ThroughputBucket = { t: number; auth: number; process: number; network_flow: number };

export type FleetSnapshot = {
  hosts: FleetHost[];
  by_type: Partial<Record<EventType, number>>;
  series: ThroughputBucket[];
  rate_epm: number;
};

export type Status = {
  mode: "warmup" | "monitoring";
  events_seen: number;
  warmup_remaining_s: number;
  warmup_seconds: number;
  incident_count: number;
  high_confidence_count: number;
  flagged_recent: number;
  baseline_ready: boolean;
  fleet: FleetSnapshot;
  pipeline: PipelineInfo;
};

export type TapeEvent = {
  timestamp: string;
  event_type: EventType;
  phase: string;
  source: string;
  actor: string | null;
  detail: string;
  host: string;
  flagged: boolean;
  incident?: string;
};

export type PipelineActivity = { t: string; stage: string; msg: string };

export type PipelineInfo = {
  stats: Record<string, number>;
  activity: PipelineActivity[];
  window_seconds: number;
  process_baseline_size: number;
  detectors: { auth: boolean; network: boolean };
};

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
  end: string;
  phases: string[];
  sources: string[];
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
export const getDemoIncidents = () => get<IncidentSummary[]>("/api/demo/incidents");
export const getIncident = (id: string) => get<IncidentDetail>(`/api/incidents/${id}`);
export const getStatus = () => get<Status>("/api/status");
export const getRecentEvents = (limit = 100) => get<TapeEvent[]>(`/api/events/recent?limit=${limit}`);
export const getFlaggedEvents = () => get<TapeEvent[]>("/api/events/flagged");
export const getIncidentEvents = (high = false) =>
  get<TapeEvent[]>(`/api/events/incidents${high ? "?high=true" : ""}`);
