import { API_BASE, type IncidentSummary, type ResponseAction, type TapeEvent } from "./api";

export type StreamEvent =
  | ({ type: "incident" } & IncidentSummary)
  | { type: "telemetry"; events: TapeEvent[] }
  | { type: "attribution"; id: string; [k: string]: unknown }
  | ({ type: "action" } & ResponseAction)
  | { type: "warning"; reason: string; [k: string]: unknown };

// Subscribe to the live SSE stream. EventSource auto-reconnects on drop.
export function subscribe(
  onEvent: (e: StreamEvent) => void,
  onLink?: (up: boolean) => void,
): () => void {
  const es = new EventSource(`${API_BASE}/api/stream`);
  es.onopen = () => onLink?.(true);
  es.onerror = () => onLink?.(false);
  es.onmessage = (m) => {
    onLink?.(true); // a frame arriving proves the stream is up even if onopen was missed
    try {
      onEvent(JSON.parse(m.data) as StreamEvent);
    } catch {
      /* ignore malformed frame */
    }
  };
  return () => es.close();
}
