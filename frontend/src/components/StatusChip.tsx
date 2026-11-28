import "./status.css";
import { VERDICT_META, VerdictGlyph, type VerdictStatus } from "./VerdictGlyph";

/**
 * Review-status chip (X3, F2): the verdict glyph (shape + short word) on a neutral chip, so the
 * same verdict reads identically in the grid, viewer, review board and dashboard — and without
 * colour. Colours come from the `--status-*` tokens and only repeat the shape.
 *
 *   import { StatusChip, STATUS_META } from "../components/StatusChip";
 *   <StatusChip status="relevant" />          // ◆ 관련
 *   <StatusChip status="include-in-report" /> // 보고서 (page outline)
 *
 * For a toggle button, set `data-status-button={status}` and `aria-pressed`
 * (status.css fills it with the status colour when pressed).
 */
export type ChipStatus = VerdictStatus;

const TOKENS: Record<ChipStatus, { token: string; onToken: string }> = {
  relevant: { token: "--status-relevant", onToken: "--status-relevant-on" },
  bookmark: { token: "--status-bookmark", onToken: "--status-bookmark-on" },
  excluded: { token: "--status-excluded", onToken: "--status-excluded-on" },
  "needs-review": { token: "--status-needs-review", onToken: "--status-needs-review-on" },
  "include-in-report": { token: "--status-report", onToken: "--status-report-on" },
};

export const STATUS_META: Record<
  ChipStatus,
  { label: string; short: string; token: string; onToken: string }
> = Object.fromEntries(
  (Object.keys(TOKENS) as ChipStatus[]).map((status) => [
    status,
    { ...VERDICT_META[status], ...TOKENS[status] },
  ]),
) as Record<ChipStatus, { label: string; short: string; token: string; onToken: string }>;

export { isVerdictStatus as isChipStatus } from "./VerdictGlyph";

export function StatusChip({ status, label }: { status: ChipStatus; label?: string }) {
  return (
    <span className="status-chip" data-status={status} title={STATUS_META[status].label}>
      <VerdictGlyph status={status} withLabel label={label} />
    </span>
  );
}
