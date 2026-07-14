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

export function TopBar({ link, nav = false }: { link?: LinkState; nav?: boolean }) {
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
      </div>
      <span className="spacer" />
      {link !== undefined && <span className={`chip link ${link}`}>{LINK_LABEL[link]}</span>}
      {nav && (
        <>
          <Link href="/telemetry" className="chip navlink">TELEMETRY</Link>
          <Link href="/report" className="chip navlink">REPORT</Link>
          <Link href="/demo" className="chip navlink">DEMO</Link>
        </>
      )}
      <span className="chip utc mono">{utc ?? "--:--:--"} UTC</span>
    </header>
  );
}
