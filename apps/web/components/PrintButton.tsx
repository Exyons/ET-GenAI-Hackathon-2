"use client";

export function PrintButton() {
  return (
    <button type="button" className="printbtn" onClick={() => window.print()}>
      Save as PDF ▸
    </button>
  );
}
