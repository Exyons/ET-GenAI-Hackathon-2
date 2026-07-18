"use client";

import { useEffect, useState } from "react";

import { NetworkModal } from "./NetworkModal";

// Single, page-level host for the network-address modal. IpChip fires a window
// event; this renders the modal once, at the top of the DOM — so it never inherits
// the tape row's nowrap/overflow, and it survives the tape re-rendering underneath.
export const IP_MODAL_EVENT = "prahari:open-ip";

export function IpModalHost() {
  const [ip, setIp] = useState<string | null>(null);
  useEffect(() => {
    const open = (e: Event) => setIp((e as CustomEvent<string>).detail);
    window.addEventListener(IP_MODAL_EVENT, open);
    return () => window.removeEventListener(IP_MODAL_EVENT, open);
  }, []);
  if (!ip) return null;
  return <NetworkModal ip={ip} onClose={() => setIp(null)} />;
}
