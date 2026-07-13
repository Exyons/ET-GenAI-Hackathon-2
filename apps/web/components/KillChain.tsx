import type { TapeEvent } from "../lib/api";

const PHASES = [
  { key: "lateral_movement", label: "Lateral movement" },
  { key: "discovery", label: "Discovery" },
  { key: "execution", label: "Execution" },
  { key: "command_and_control", label: "Command & control" },
] as const;

export function KillChain({ events }: { events: TapeEvent[] }) {
  const flagged = events.filter((e) => e.flagged);
  const counts = new Map<string, number>();
  for (const e of flagged) counts.set(e.phase, (counts.get(e.phase) ?? 0) + 1);

  return (
    <section className="killchain" aria-label="Kill-chain phases with flagged event counts">
      <div className="kc-label">
        <span className="eyebrow">Kill chain</span>
        <span className="mono dim">flagged events · rolling window</span>
      </div>
      {PHASES.map((p, i) => {
        const n = counts.get(p.key) ?? 0;
        return (
          <div key={p.key} className={`kc-seg ${p.key}${n > 0 ? " lit" : ""}`}>
            <div className="kc-n mono">{n}</div>
            <div className="kc-name">{p.label}</div>
            {i < PHASES.length - 1 && <span className="kc-arrow">▸</span>}
          </div>
        );
      })}
    </section>
  );
}
