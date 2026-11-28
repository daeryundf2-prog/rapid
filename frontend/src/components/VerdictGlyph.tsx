import "./status.css";

/**
 * Verdict glyph (F2): one shape + one short word per review verdict, the same on every screen
 * (grid select column, 선별 chip, cards, thumbnails, menus, viewer, dashboard, review board).
 * The shape carries the meaning without colour (greyscale, 1.4.1): ◆ 관련 (filled diamond),
 * ◐ 재검토 (half-filled circle), ⊘ 제외 (slashed ring, neutral), 북마크 (filled ribbon),
 * 보고서 (page outline). The colour (`--status-*`) only repeats it.
 *
 *   <VerdictGlyph status="relevant" />            // shape only; the full label is screen-reader text
 *   <VerdictGlyph status="relevant" withLabel />  // shape + short word ("관련")
 *
 * The svg is aria-hidden; the label is real text (visible, or visually hidden).
 */
export type VerdictStatus = "relevant" | "bookmark" | "excluded" | "needs-review" | "include-in-report";

export const VERDICT_META: Record<VerdictStatus, { label: string; short: string }> = {
  relevant: { label: "관련 있음", short: "관련" },
  "needs-review": { label: "재검토", short: "재검토" },
  excluded: { label: "제외", short: "제외" },
  bookmark: { label: "북마크", short: "북마크" },
  "include-in-report": { label: "보고서 포함", short: "보고서" },
};

export function isVerdictStatus(value: unknown): value is VerdictStatus {
  return typeof value === "string" && Object.hasOwn(VERDICT_META, value);
}

/** The 14×14 shape of a verdict (stroke/fill = currentColor, set per status in status.css). */
export function VerdictShape({ status }: { status: VerdictStatus }) {
  return (
    <svg
      className="verdict-shape"
      viewBox="0 0 14 14"
      width="14"
      height="14"
      aria-hidden="true"
      focusable="false"
      data-verdict={status}
    >
      {status === "relevant" ? <path d="M7 1 L13 7 L7 13 L1 7 Z" fill="currentColor" /> : null}
      {status === "needs-review" ? (
        <>
          <circle cx="7" cy="7" r="5.25" fill="none" stroke="currentColor" strokeWidth="1.5" />
          <path d="M7 1.75 A5.25 5.25 0 0 0 7 12.25 Z" fill="currentColor" />
        </>
      ) : null}
      {status === "excluded" ? (
        <>
          <circle cx="7" cy="7" r="5.25" fill="none" stroke="currentColor" strokeWidth="1.5" />
          <path d="M3.3 10.7 L10.7 3.3" stroke="currentColor" strokeWidth="1.5" />
        </>
      ) : null}
      {status === "bookmark" ? <path d="M3 1 H11 V13 L7 9.5 L3 13 Z" fill="currentColor" /> : null}
      {status === "include-in-report" ? (
        <path
          d="M2.75 1.75 H8.5 L11.25 4.5 V12.25 H2.75 Z M5 6.5 H9 M5 9 H9"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
      ) : null}
    </svg>
  );
}

export function VerdictGlyph({
  status,
  withLabel = false,
  label,
}: {
  status: VerdictStatus;
  /** Show the short word next to the shape (else the full label is screen-reader only). */
  withLabel?: boolean;
  /** Visible word instead of the short one (a tag that maps onto a verdict, e.g. "bookmark"). */
  label?: string;
}) {
  const meta = VERDICT_META[status];
  return (
    <span className="verdict" data-verdict={status} title={withLabel ? undefined : meta.label}>
      <VerdictShape status={status} />
      {withLabel ? (
        <span className="verdict-word">{label ?? meta.short}</span>
      ) : (
        <span className="visually-hidden">{meta.label}</span>
      )}
    </span>
  );
}
