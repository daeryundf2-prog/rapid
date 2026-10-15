/** Product mark (visual-polish S7/S10): a rounded accent tile with an "R" scan stroke, plus the wordmark. */

export function BrandMark({ size = 22 }: { size?: number }) {
  return (
    <svg
      className="brand-mark"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      aria-hidden="true"
      focusable="false"
    >
      <rect x="1.5" y="1.5" width="21" height="21" rx="6" fill="var(--accent)" />
      <path
        d="M8.5 17.5v-11h4.25a3.25 3.25 0 0 1 0 6.5H8.5m4.5 0 3.5 4.5"
        fill="none"
        stroke="var(--on-accent)"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Mark + "RapidForensic" wordmark. */
export function Brand({ size = 22 }: { size?: number }) {
  return (
    <span className="brand">
      <BrandMark size={size} />
      <span className="brand-word">
        Rapid<span className="brand-word-strong">Forensic</span>
      </span>
    </span>
  );
}
