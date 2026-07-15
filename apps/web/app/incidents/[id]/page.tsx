import Link from "next/link";

import { IpChip } from "../../../components/IpChip";
import { ResponsePanel } from "../../../components/ResponsePanel";
import { TopBar } from "../../../components/TopBar";
import { getIncident, type EventView, type IncidentDetail } from "../../../lib/api";

export const dynamic = "force-dynamic";

const SOURCE_LABEL: Record<string, string> = {
  lanl: "Auth · LANL",
  otrf: "Process · Sysmon",
  cicids: "Network · NetFlow",
  "linux-auth": "Auth · sshd",
  "linux-audit": "Process · auditd",
  "linux-conntrack": "Network · conntrack",
  "windows-security": "Auth · Security log",
  "windows-sysmon": "Sysmon",
  sysmon: "Process · Sysmon",
  conntrack: "Network · conntrack",
};

function clock(iso: string): string {
  return new Date(iso).toISOString().slice(11, 19);
}

function Detail({ e }: { e: EventView }) {
  // make the destination IP clickable for offline network enrichment
  if (e.dst_ip && e.detail.includes(e.dst_ip)) {
    const [before, after] = e.detail.split(e.dst_ip);
    return <b>{before}<IpChip ip={e.dst_ip} />{after}</b>;
  }
  return <b>{e.detail}</b>;
}

function TimelineEvent({ e, hot }: { e: EventView; hot: boolean }) {
  return (
    <div className={`evt${hot ? " hot" : ""}`}>
      <div className="t">{clock(e.timestamp)}</div>
      <span className="node" />
      <div className="card">
        <div className="src">{SOURCE_LABEL[e.source] ?? e.source}</div>
        <div className="desc">{e.actor ? `${e.actor} · ` : ""}<Detail e={e} /></div>
        <span className={`phase ${e.phase}`}>{e.phase.replace(/_/g, " ")}</span>
      </div>
    </div>
  );
}

export default async function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let d: IncidentDetail | null = null;
  let error = "";
  try {
    d = await getIncident(id);
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  if (!d) {
    return (
      <main className="wrap">
        <TopBar />
        <p style={{ color: "var(--haze)", marginTop: 28 }} className="mono">
          Incident unavailable — {error}
        </p>
        <Link href="/" className="back">◂ back to command view</Link>
      </main>
    );
  }

  const s = d.summary;
  const a = d.attribution;

  return (
    <main className="wrap">
      <TopBar />

      <div className="banner">
        <div>
          <div className="eyebrow">Active incident · {[...new Set(d.timeline.map((e) => e.phase))].join(" → ").replace(/_/g, " ")}</div>
          <div className="entity"><span className="lbl">ENTITY</span>{s.entity}</div>
        </div>
        {s.high_confidence && <span className="pill hi">● HIGH-CONFIDENCE</span>}
        {s.is_true_positive && <span className="pill rt">RED-TEAM CONFIRMED</span>}
        <div className="compound">
          <div className="val">{s.compound_score.toFixed(2)}</div>
          <div className="cap">Compound score</div>
        </div>
      </div>

      <ResponsePanel incidentId={s.id} />

      <div className="grid">
        <div className="panel">
          <h2>Fused timeline <span className="hint">— one entity · {s.source_count} sensors · {d.timeline.length} events</span></h2>
          <div className="spine spine-scroll">
            <div className="rail" />
            {d.timeline.map((e, idx) => (
              <TimelineEvent key={idx} e={e} hot={idx === d.timeline.length - 1} />
            ))}
            <div className="converge">
              <div className="k">Correlated: <b>{s.source_count} sensors · {s.phase_count} kill-chain phases</b> on one host.</div>
              <div className="sub">Each event alone is unremarkable — signature baseline stayed silent.</div>
            </div>
          </div>
        </div>

        <div className="panel">
          <h2>ATT&amp;CK attribution <span className="hint">— grounded RAG</span></h2>
          <div className="pad">
            {a.techniques.length > 0 ? (
              a.techniques.map((t) => (
                <div className="tech" key={t.id}>
                  <div className="id">{t.id}</div>
                  <div><div className="nm">{t.name}</div><div className="tac">tactic · {t.tactic}</div></div>
                </div>
              ))
            ) : (
              <p style={{ color: "var(--haze)", fontSize: 13 }}>No attribution for this incident.</p>
            )}

            {a.grounded && <div className="grounded">✓ grounded — every technique cited from the retrieved ATT&amp;CK set</div>}
            {a.explanation && <p className="explain">{a.explanation}</p>}

            {a.predicted_next && (
              <div className="next">
                <div className="lbl">Predicted next tactic</div>
                <div className="val">{[...new Set(d.timeline.map((e) => e.phase))].slice(-1)[0]?.replace(/_/g, "-")} → <b>{a.predicted_next}</b></div>
              </div>
            )}
          </div>
        </div>
      </div>

      <Link href="/" className="back">◂ back to command view</Link>
    </main>
  );
}
