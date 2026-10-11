import "./status.css";

/**
 * Review-status chip (X3). Colours come from the `--status-*` tokens, so the
 * same status looks identical in the grid, viewer, review board and dashboard.
 *
 *   import { StatusChip, STATUS_META } from "../components/StatusChip";
 *   <StatusChip status="relevant" />          // 관련 있음 (red)
 *   <StatusChip status="include-in-report" /> // 보고서 포함 (purple)
 *
 * For a toggle button, set `data-status-button={status}` and `aria-pressed`
 * (status.css fills it with the status colour when pressed).
 */
export type ChipStatus = "relevant" | "bookmark" | "excluded" | "needs-review" | "include-in-report";

export const STATUS_META: Record<ChipStatus, { label: string; token: string; onToken: string }> = {
  relevant: { label: "관련 있음", token: "--status-relevant", onToken: "--status-relevant-on" },
  bookmark: { label: "북마크", token: "--status-bookmark", onToken: "--status-bookmark-on" },
  excluded: { label: "제외", token: "--status-excluded", onToken: "--status-excluded-on" },
  "needs-review": { label: "재검토", token: "--status-needs-review", onToken: "--status-needs-review-on" },
  "include-in-report": { label: "보고서 포함", token: "--status-report", onToken: "--status-report-on" },
};

export function isChipStatus(value: unknown): value is ChipStatus {
  return typeof value === "string" && Object.hasOwn(STATUS_META, value);
}

export function StatusChip({ status, label }: { status: ChipStatus; label?: string }) {
  return (
    <span className="status-chip" data-status={status}>
      {label ?? STATUS_META[status].label}
    </span>
  );
}
