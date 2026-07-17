import type { TapeEvent } from "../lib/api";
import { clock, shortSource } from "../lib/format";
import { IpChip } from "./IpChip";

const TYPE_CLS: Record<string, string> = {
  auth: "s-auth",
  process: "s-proc",
  network_flow: "s-net",
};

// Render the event detail, turning an embedded destination IP into a clickable
// chip that opens offline network enrichment.
function Detail({ e }: { e: TapeEvent }) {
  const text = e.detail || e.event_type;
  if (e.dst_ip && text.includes(e.dst_ip)) {
    const [before, after] = text.split(e.dst_ip);
    return <>{before}<IpChip ip={e.dst_ip} />{after}</>;
  }
  return <>{text}</>;
}

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
            {e.incident && <a href={`/incidents/${e.incident}`} className="incchip mono">{e.incident}</a>}
            {e.actor ? <b className="actor mono">{e.actor}</b> : null}
            {e.actor ? " · " : ""}
            <Detail e={e} />
          </span>
          {e.flagged ? <span className="flag mono">⚑ FLAG</span> : <span aria-hidden />}
          <span className="srctag mono">{shortSource(e.source)}</span>
        </div>
      ))}
    </div>
  );
}
