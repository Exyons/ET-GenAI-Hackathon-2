// Inline-SVG icons. Emoji/symbol glyphs (⚙ ☀ ☾ ⚑ …) tofu on systems without an
// emoji font; SVG renders identically everywhere and inherits color + size (1em).
export type IconName =
  | "gear" | "sun" | "moon" | "flag" | "warn" | "refresh" | "undo"
  | "chevron" | "summary" | "tape" | "check" | "x" | "block";

const PATHS: Record<IconName, string> = {
  gear:
    "M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z" +
    " M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z",
  sun:
    "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10z M12 1v2 M12 21v2 M4.2 4.2l1.4 1.4 M18.4 18.4l1.4 1.4" +
    " M1 12h2 M21 12h2 M4.2 19.8l1.4-1.4 M18.4 5.6l1.4-1.4",
  moon: "M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z",
  flag: "M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z M4 22v-7",
  warn: "M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z M12 9v4 M12 17h.01",
  refresh: "M23 4v6h-6 M20.49 15a9 9 0 1 1-2.12-9.36L23 10",
  undo: "M1 4v6h6 M3.51 15a9 9 0 1 0 2.13-9.36L1 10",
  chevron: "M9 18l6-6-6-6",
  summary: "M3 3h7v7H3z M14 3h7v7h-7z M14 14h7v7h-7z M3 14h7v7H3z",
  tape: "M8 6h13 M8 12h13 M8 18h13 M3 6h.01 M3 12h.01 M3 18h.01",
  check: "M20 6 9 17l-5-5",
  x: "M18 6 6 18 M6 6l12 12",
  block: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z M4.9 4.9l14.2 14.2",
};

// deg rotation for the reusable chevron
const ROTATE: Record<string, number> = { up: -90, right: 0, down: 90, left: 180 };

export function Icon({ name, dir, className, size = "1em" }: {
  name: IconName; dir?: "up" | "right" | "down" | "left"; className?: string; size?: string | number;
}) {
  return (
    <svg
      className={`icon${className ? ` ${className}` : ""}`} viewBox="0 0 24 24" width={size} height={size}
      fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"
      aria-hidden="true" focusable="false"
      style={dir ? { transform: `rotate(${ROTATE[dir]}deg)` } : undefined}
    >
      {PATHS[name].split(" M").map((seg, i) => <path key={i} d={i === 0 ? seg : "M" + seg} />)}
    </svg>
  );
}
