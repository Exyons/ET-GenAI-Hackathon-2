"use client";

import { IP_MODAL_EVENT } from "./IpModalHost";

// A clickable IP that opens offline network enrichment. Fires a window event so a
// single page-level host renders the modal — see IpModalHost. That keeps the modal
// out of the tape row (whose nowrap/overflow it would otherwise inherit) and alive
// while the tape re-renders underneath. Reusable in the timeline, response panel,
// tape and summary table.
export function IpChip({ ip }: { ip: string }) {
  return (
    <button type="button" className="ipchip mono" title="network connection detail"
      onClick={() => window.dispatchEvent(new CustomEvent(IP_MODAL_EVENT, { detail: ip }))}>
      {ip}
    </button>
  );
}
