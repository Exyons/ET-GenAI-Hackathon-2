import Link from "next/link";

import { AutoRefresh } from "../../../components/AutoRefresh";
import { Help } from "../../../components/Help";
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
      <AutoRefresh />

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
          <h2>Fused timeline
            <Help text="Every flagged event for this host, from all sensors, on one timeline. Correlating them is what turns unremarkable individual events into a detected incident." wide />
            <span className="hint">— {s.source_count} sensors · {d.timeline.length} events</span></h2>
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
          <h2>ATT&amp;CK attribution
            <Help wide align="right" text="MITRE ATT&CK is the standard catalogue of attacker techniques. The local model mapped this incident's timeline to it. Every technique is grounded — cited from doctrine retrieved for this incident, never invented." />
          </h2>
          <div className="pad">
            {a.explanation ? (
              <div className="assessment">
                <div className="assessment-head">What happened</div>
                <p>{a.explanation}</p>
              </div>
            ) : a.techniques.length > 0 ? (
              <div className="assessment muted">
                <div className="assessment-head">What happened</div>
                <p>Awaiting the local model&apos;s written assessment — refreshes automatically. Techniques below are mapped from retrieval.</p>
              </div>
            ) : null}

            {a.techniques.length > 0 ? (
              <div className="techlist">
                <div className="techlist-head">Mapped techniques
                  <Help text="Hover a technique's ? for a plain-English description of what it is." />
                </div>
                {a.techniques.map((t) => (
                  <div className="tech" key={t.id}>
                    <div className="id">{t.id}</div>
                    <div className="tbody">
                      <div className="nm">{t.name}{t.description && <Help text={t.description} align="right" wide />}</div>
                      <div className="tac">tactic · {t.tactic}</div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ color: "var(--haze)", fontSize: 13 }}>No attribution for this incident.</p>
            )}

            {a.grounded && <div className="grounded">✓ grounded — every technique cited from the retrieved ATT&amp;CK set</div>}

            {a.predicted_next && (
              <div className="next">
                <div className="lbl">Predicted next tactic
                  <Help align="right" wide text="Learned from how ATT&CK tactics commonly chain across intrusions — the attacker's most likely next move. Prioritise detection and threat-hunting for this tactic now." />
                </div>
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
