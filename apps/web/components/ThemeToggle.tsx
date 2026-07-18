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
    return (
      <button type="button" className="chip theme-chip" onClick={toggle} aria-label="Toggle theme">
        <Icon name={theme === "dark" ? "moon" : "sun"} /> {theme === "dark" ? "Dark" : "Light"}
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
