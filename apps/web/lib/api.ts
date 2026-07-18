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
  response: ResponseStats;
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
  dst_ip?: string | null;
};

export type PipelineActivity = { t: string; stage: string; msg: string };

export type PipelineInfo = {
  stats: Record<string, number>;
  activity: PipelineActivity[];
  window_seconds: number;
  process_baseline_size: number;
  detectors: { auth: boolean; network: boolean };
  models: { chat: string; embed: string };
  attribution_error: string | null;
};

export type ResponseStats = {
  total: number;
  pending: number;
  approved: number;
  executed: number;
  failed: number;
  rejected: number;
  reverted: number;
};

export type SummaryDigest = {
  mode: string;
  baseline_ready: boolean;
  events_seen: number;
  rate_epm: number;
  hosts: number;
  hosts_online: number;
  flagged_recent: number;
  incident_count: number;
  high_confidence_count: number;
  phase_counts: Record<string, number>;
  flag_reasons: Record<string, number>;
  response: ResponseStats;
  top_incidents: { entity: string; id: string; score: number; high_confidence: boolean; sources: number; phases: number }[];
  attribution_error: string | null;
};

export type SituationSummary = {
  digest: SummaryDigest;
  narrative: string;
  generated_at: string | null;
  stale: boolean;
  generating: boolean;
  error: string | null;
  model: string;
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
  dst_ip: string | null;
};

export type PlaybookInfo = { title: string; reversible: boolean; what: string; impact: string };

export type NetworkFlow = {
  ts: string;
  dst_ip: string;
  src_host: string | null;
  src_internal: boolean | null;
  bytes: number | null;
  duration: number | null;
  flagged: boolean;
};

export type NetworkDetail = {
  ip: string;
  klass: string;
  label: string;
  scope: string;
  provider: string;
  provider_type: string;
  country: string;
  city: string;
  reputation: { listed: boolean; sources: string[] };
  verdict: string;
  severity: "good" | "neutral" | "bad" | string;
  online_enriched: boolean;
  flow_count: number;
  hosts: string[];
  total_bytes: number;
  first_seen: string | null;
  last_seen: string | null;
  any_flagged: boolean;
  flows: NetworkFlow[];
};

export type TechniqueView = { id: string; name: string; tactic: string; description: string };

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

export type ActionStatus =
  | "pending_approval" | "approved" | "dispatched" | "executed" | "failed" | "rejected" | "reverted";

export type ActionResult = {
  ran: boolean;
  dry_run: boolean;
  command?: string;
  stdout?: string;
  exit_code?: number | null;
  error?: string | null;
  note?: string;
};

export type ResponseAction = {
  id: string;
  incident_id: string;
  host: string;
  playbook: string;
  target: string;
  reason: string;
  reversible: boolean;
  status: ActionStatus;
  mode: "dry_run" | "armed";
  undo: boolean;
  created_at: string;
  approver: string | null;
  result: ActionResult | null;
  revert_of: string | null;
};

export const PLAYBOOK_TITLE: Record<string, string> = {
  isolate_host: "Isolate host",
  block_ip: "Block address",
  disable_account: "Disable account",
  kill_process: "Kill process",
  snapshot: "Snapshot / forensics",
};

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
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

export const getSummary = (refresh = false) =>
  get<SituationSummary>(`/api/summary${refresh ? "?refresh=true" : ""}`);
export const exportUrl = (view: "recent" | "flagged", format: "json" | "csv") =>
  `${API_BASE}/api/events/export?view=${view}&format=${format}`;
export const getPlaybooks = () => get<Record<string, PlaybookInfo>>("/api/playbooks");

export type ThreatIntelStatus = {
  last_update: string | null;
  configured_feeds: string[];
  refresh_hours: number;
  blocklist_entries: number;
  blocklist_sources: string[];
  feeds: Record<string, { ok: boolean; entries: number; error: string | null; at: string }>;
};
export const getThreatIntel = () => get<ThreatIntelStatus>("/api/threatintel");
export const addToBlocklist = (ip: string, note = "") =>
  post<ThreatIntelStatus>("/api/threatintel/blocklist", { ip, note });
export const getNetworkDetail = (ip: string) => get<NetworkDetail>(`/api/network/${encodeURIComponent(ip)}`);
export const getActions = (incident?: string) =>
  get<ResponseAction[]>(`/api/actions${incident ? `?incident=${encodeURIComponent(incident)}` : ""}`);
export const approveAction = (id: string, arm: boolean) =>
  post<ResponseAction>(`/api/actions/${id}/approve`, { approver: "operator", arm });
export const rejectAction = (id: string) =>
  post<ResponseAction>(`/api/actions/${id}/reject`, { approver: "operator" });
export const revertAction = (id: string) =>
  post<ResponseAction>(`/api/actions/${id}/revert`, { approver: "operator" });
