"use client";

import { useState } from "react";

import { NetworkModal } from "./NetworkModal";

// A clickable IP that opens offline network enrichment. Reusable in the timeline,
// the response panel and the tape.
export function IpChip({ ip }: { ip: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" className="ipchip mono" onClick={() => setOpen(true)}
        title="network connection detail">{ip}</button>
      {open && <NetworkModal ip={ip} onClose={() => setOpen(false)} />}
    </>
  );
}
