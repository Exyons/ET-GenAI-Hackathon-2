// A small "?" that reveals a description on hover/focus. Pure CSS (no client JS),
// so it works inside server components. Keeps panels uncluttered — detail on demand.
export function Help({ text, wide, align = "center" }: {
  text: string; wide?: boolean; align?: "center" | "right";
}) {
  return (
    <span className="help" tabIndex={0} role="note" aria-label={text}>
      ?
      <span className={`help-bubble${wide ? " wide" : ""}${align === "right" ? " right" : ""}`}>{text}</span>
    </span>
  );
}
