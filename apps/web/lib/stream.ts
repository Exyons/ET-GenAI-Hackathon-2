import { API_BASE, type IncidentSummary } from "./api";

export type StreamEvent =
  | ({ type: "incident" } & IncidentSummary)
  | { type: "attribution"; id: string; [k: string]: unknown }
  | { type: "warning"; reason: string; [k: string]: unknown };

// Subscribe to the live SSE stream. EventSource auto-reconnects on drop.
export function subscribe(onEvent: (e: StreamEvent) => void): () => void {
  const es = new EventSource(`${API_BASE}/api/stream`);
  es.onmessage = (m) => {
    try {
      onEvent(JSON.parse(m.data) as StreamEvent);
    } catch {
      /* ignore malformed frame */
    }
  };
  return () => es.close();
}
