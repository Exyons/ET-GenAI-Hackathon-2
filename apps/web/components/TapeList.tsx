import type { TapeEvent } from "../lib/api";
import { clock, shortSource } from "../lib/format";

const TYPE_CLS: Record<string, string> = {
  auth: "s-auth",
  process: "s-proc",
  network_flow: "s-net",
};

// Newest-first rows of raw telemetry. Used inside fleet host entries and on /telemetry.
export function TapeList({ events, showHost = true }: { events: TapeEvent[]; showHost?: boolean }) {
  if (events.length === 0) {
    return <div className="empty"><p className="mono dim">awaiting telemetry…</p></div>;
  }
  return (
    <div className="tape" aria-live="off">
      {events.map((e, i) => (
        <div key={`${e.timestamp}-${i}`} className={`tick${e.flagged ? " flagged" : ""}${showHost ? "" : " nohost"}`}>
          <span className="t mono">{clock(e.timestamp)}</span>
          <i className={`swatch ${TYPE_CLS[e.event_type] ?? ""}`} />
          {showHost && <span className="host mono">{e.host}</span>}
          <span className="what">
            {e.actor ? <b className="actor mono">{e.actor}</b> : null}
            {e.actor ? " · " : ""}
            {e.detail || e.event_type}
          </span>
          {e.flagged ? <span className="flag mono">⚑ FLAG</span> : <span aria-hidden />}
          <span className="srctag mono">{shortSource(e.source)}</span>
        </div>
      ))}
    </div>
  );
}
