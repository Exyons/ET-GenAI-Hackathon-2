"use client";

import { useEffect, useState } from "react";

import { Icon } from "./Icon";

export type Theme = "dark" | "light";
const KEY = "prahari-theme";

function apply(t: Theme) {
  document.documentElement.setAttribute("data-theme", t);
  try { localStorage.setItem(KEY, t); } catch { /* ignore */ }
}

// Blocks the flash of the wrong theme: runs before paint, in <head>, using only
// what's available pre-hydration. Kept in sync with the toggle's storage key.
export const THEME_SCRIPT =
  `try{var t=localStorage.getItem('${KEY}')||'dark';document.documentElement.setAttribute('data-theme',t);}catch(e){}`;

export function ThemeToggle({ compact = false }: { compact?: boolean }) {
  const [theme, setTheme] = useState<Theme>("dark");
  useEffect(() => {
    const t = (document.documentElement.getAttribute("data-theme") as Theme) || "dark";
    setTheme(t);
  }, []);
  const toggle = () => { const next: Theme = theme === "dark" ? "light" : "dark"; setTheme(next); apply(next); };
  if (compact) {
    const next = theme === "dark" ? "light" : "dark";
    return (
      <button type="button" className={`theme-btn ${theme}`} onClick={toggle}
        aria-label={`Switch to ${next} theme`} title={`Switch to ${next} theme`}>
        {/* one glyph morphs into the other: the moon is a disc with a bite taken
            out of it by the mask circle, which slides away to leave a sun */}
        <svg viewBox="0 0 24 24" className="theme-svg" aria-hidden="true">
          <mask id="theme-cut">
            <rect x="0" y="0" width="24" height="24" fill="white" />
            <circle className="theme-bite" cx="18" cy="7" r="8" fill="black" />
          </mask>
          <circle className="theme-disc" cx="12" cy="12" r="9" mask="url(#theme-cut)" />
          <g className="theme-rays" strokeLinecap="round">
            <line x1="12" y1="0.5" x2="12" y2="3" />
            <line x1="12" y1="21" x2="12" y2="23.5" />
            <line x1="0.5" y1="12" x2="3" y2="12" />
            <line x1="21" y1="12" x2="23.5" y2="12" />
            <line x1="4.2" y1="4.2" x2="6" y2="6" />
            <line x1="18" y1="18" x2="19.8" y2="19.8" />
            <line x1="4.2" y1="19.8" x2="6" y2="18" />
            <line x1="18" y1="6" x2="19.8" y2="4.2" />
          </g>
        </svg>
      </button>
    );
  }
  return (
    <div className="theme-switch">
      <button type="button" className={`tsw${theme === "dark" ? " on" : ""}`} onClick={() => { setTheme("dark"); apply("dark"); }}><Icon name="moon" /> Dark</button>
      <button type="button" className={`tsw${theme === "light" ? " on" : ""}`} onClick={() => { setTheme("light"); apply("light"); }}><Icon name="sun" /> Light</button>
    </div>
  );
}
