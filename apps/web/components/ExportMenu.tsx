"use client";

import { useEffect, useRef, useState } from "react";

import { exportUrl } from "../lib/api";

// Downloads the retained telemetry as a file. Links hit /api/events/export which
// sets Content-Disposition, so the browser saves rather than navigates.
export function ExportMenu() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onClick = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  return (
    <div className="exportwrap" ref={ref}>
      <button type="button" className="exportbtn" onClick={() => setOpen((v) => !v)}>Export ▾</button>
      {open && (
        <div className="exportmenu">
          <div className="grp">Recent telemetry</div>
          <a href={exportUrl("recent", "json")} download>JSON</a>
          <a href={exportUrl("recent", "csv")} download>CSV</a>
          <div className="grp">Flagged (correlation window)</div>
          <a href={exportUrl("flagged", "json")} download>JSON</a>
          <a href={exportUrl("flagged", "csv")} download>CSV</a>
        </div>
      )}
    </div>
  );
}
