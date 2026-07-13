import type { Metrics } from "../lib/api";

export function Benchmark({ m }: { m: Metrics | null }) {
  if (!m) return null;
  return (
    <section className="bench">
      <span className="eyebrow">Recorded LANL red-team benchmark</span>
      <span className="mono"><b className="good">{m.behavioural_recall.toFixed(2)}</b> behavioural recall</span>
      <span className="mono"><b className="bad">{m.signature_recall.toFixed(2)}</b> signature recall</span>
      <span className="mono"><b className="amp">{m.mttd_seconds}s</b> MTTD</span>
      <span className="mono"><b className="amp">{(m.false_positive_rate * 100).toFixed(1)}%</b> FP rate</span>
      <span className="mono"><b className="amp">{m.attack_techniques}</b> ATT&amp;CK techniques · air-gapped RAG</span>
    </section>
  );
}
