"use client";

import { useEffect, useRef, useState } from "react";

import { getNetworkDetail, type NetworkDetail } from "../lib/api";
import { clock, compact } from "../lib/format";

const SEV_CLS: Record<string, string> = { bad: "err", good: "ok", neutral: "warn" };

function fmtBytes(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} MB`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)} KB`;
  return `${n} B`;
}

export function NetworkModal({ ip, onClose }: { ip: string; onClose: () => void }) {
  const [d, setD] = useState<NetworkDetail | null>(null);
  const [err, setErr] = useState(false);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeRef.current?.focus();
    getNetworkDetail(ip).then(setD).catch(() => setErr(true));
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [ip, onClose]);

  const sevCls = d ? SEV_CLS[d.severity] ?? "" : "";
  const geo = d ? [d.city, d.country].filter(Boolean).join(", ") : "";

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal st-net-detail" role="dialog" aria-modal="true" aria-label={`Address ${ip}`}
        onClick={(e) => e.stopPropagation()}>
        <div className="modal-accent" />
        <div className="modal-head">
          <div>
            <div className="modal-eyebrow mono">NETWORK ADDRESS · OFFLINE ENRICHMENT</div>
            <h3 className="modal-title mono">{ip}</h3>
          </div>
          {d && <span className={`stage-state mono${sevCls ? ` ${sevCls}` : ""}`}>{d.verdict}</span>}
        </div>

        {err ? (
          <p className="modal-about">Enrichment unavailable — the API is unreachable.</p>
        ) : !d ? (
          <p className="modal-about mono dim">loading…</p>
        ) : (
          <>
            <p className="modal-about">{d.label}. Enrichment is derived from local datasets — no external lookups, so it works fully air-gapped.</p>
            {d.reputation.listed && (
              <div className="rep-alert mono">⚑ Address is on {d.reputation.sources.length} blocklist{d.reputation.sources.length === 1 ? "" : "s"}: {d.reputation.sources.join(", ")}</div>
            )}
            <div className="modal-metrics">
              <div className="mm"><div className="mm-k">provider</div><div className="mm-v mono">{d.provider || "—"}{d.provider_type ? ` · ${d.provider_type}` : ""}</div></div>
              <div className="mm"><div className="mm-k">location</div><div className="mm-v mono">{geo || "no GeoIP data"}</div></div>
              <div className="mm"><div className="mm-k">connections seen</div><div className="mm-v mono">{d.flow_count}</div></div>
              <div className="mm"><div className="mm-k">data out</div><div className="mm-v mono">{fmtBytes(d.total_bytes)}</div></div>
            </div>
            {d.hosts.length > 0 && (
              <div className="modal-activity">
                <div className="modal-sub mono">HOSTS THAT CONTACTED IT</div>
                <div className="host-chips">{d.hosts.map((h) => <span key={h} className="host-chip mono">{h}</span>)}</div>
              </div>
            )}
            <div className="modal-activity">
              <div className="modal-sub mono">CONNECTIONS ({d.flow_count}{d.flow_count > d.flows.length ? `, latest ${d.flows.length}` : ""})</div>
              {d.flows.length === 0 ? (
                <div className="mono dim" style={{ fontSize: 11.5 }}>no connection records retained for this address</div>
              ) : (
                <div className="netflows">
                  {d.flows.map((f, i) => (
                    <div key={i} className="netflow mono">
                      <span className="t">{clock(f.ts)}</span>
                      <span className="h">{f.src_host ?? "?"}</span>
                      <span className="b">{f.bytes != null ? compact(f.bytes) + "B" : "—"}</span>
                      {f.flagged && <span className="fl">⚑</span>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}

        <div className="modal-foot">
          <button type="button" ref={closeRef} className="btn no" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
