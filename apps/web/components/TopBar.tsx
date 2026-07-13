"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

export type LinkState = "live" | "degraded" | "down" | "unknown";

const LINK_LABEL: Record<LinkState, string> = {
  live: "UPLINK LIVE",
  degraded: "UPLINK DEGRADED",
  down: "LINK DOWN",
  unknown: "LINKING…",
};

export function TopBar({ mode, link }: { mode?: "warmup" | "monitoring" | null; link?: LinkState }) {
  const [utc, setUtc] = useState<string | null>(null);
  useEffect(() => {
    const tick = () => setUtc(new Date().toISOString().slice(11, 19));
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <header className="topbar">
      <div className="brand">
        <span className="deva">प्रहरी</span>
        <span className="name">PRAHARI</span>
        <span className="role">SOC COMMAND · CNI</span>
      </div>
      <span className="spacer" />
      <span className="chip sovereign">SOVEREIGN · AIR-GAPPED</span>
      {mode !== undefined && (
        <span className={`chip mode ${mode ?? "off"}`}>
          <span className="dot" />
          {mode === "warmup" ? "BASELINE WARMUP" : mode === "monitoring" ? "MONITORING" : "OFFLINE"}
        </span>
      )}
      {link !== undefined && <span className={`chip link ${link}`}>{LINK_LABEL[link]}</span>}
      {mode !== undefined && <Link href="/demo" className="chip navlink">DEMO ▸</Link>}
      <span className="chip utc mono">{utc ?? "--:--:--"} UTC</span>
    </header>
  );
}
