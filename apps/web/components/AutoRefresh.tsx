"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

// Re-fetches the server-rendered page on an interval so live incidents update in
// place — deliberately slow, because the local LLM needs time to fill attribution.
export function AutoRefresh({ intervalMs = 12000 }: { intervalMs?: number }) {
  const router = useRouter();
  useEffect(() => {
    const t = setInterval(() => router.refresh(), intervalMs);
    return () => clearInterval(t);
  }, [router, intervalMs]);
  return null;
}
