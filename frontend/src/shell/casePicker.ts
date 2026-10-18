/**
 * Case picker model (review #5): the rows of the top bar's case combobox — most recent case
 * first, narrowed by the search text — and the wrap-around keyboard move.
 */

import type { RunListItem } from "../api/runs";
import { RUN_MODE_LABEL, runDisplayName } from "../app/collections";
import { statusTone } from "../components/Badge";

export interface CaseOption {
  runId: string;
  /** Evidence folder name (13px/500 first line). */
  name: string;
  /** Investigation mode label ("문서·부정 조사"), or "케이스". */
  mode: string;
  /** "2026-10-13 10:07" (local time), or "" when the run has no time stamp. */
  date: string;
  status: string;
  /** Status dot class (controls.css .status-dot.ok / .info / .danger / .warn); "" = neutral. */
  tone: string;
}

const STATUS_LABEL: Record<string, string> = {
  queued: "대기",
  running: "실행 중",
  completed: "완료",
  failed: "실패",
  cancelled: "취소됨",
  canceled: "취소됨",
  interrupted: "중단됨",
};

export function caseStatusLabel(status: string): string {
  return STATUS_LABEL[status] ?? status;
}

function pad(n: number): string {
  return String(n).padStart(2, "0");
}

/** ISO time → "YYYY-MM-DD HH:mm" in local time ("" when missing or unparsable). */
export function shortDateTime(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function timeOf(run: RunListItem): number {
  const t = Date.parse(run.updated_at ?? run.created_at ?? "");
  return Number.isNaN(t) ? Number.NEGATIVE_INFINITY : t;
}

export function toCaseOption(run: RunListItem): CaseOption {
  const mode = run.request?.mode ?? "";
  const tone = statusTone(run.status);
  return {
    runId: run.run_id,
    name: runDisplayName(run),
    mode: RUN_MODE_LABEL[mode] ?? (mode || "케이스"),
    date: shortDateTime(run.created_at ?? run.updated_at),
    status: run.status,
    tone: tone === "muted" ? "" : tone,
  };
}

/**
 * Picker rows: most recently updated/created first (stable for equal times), filtered by every
 * whitespace-separated term of `query` against the name, the mode label and the run id.
 */
export function casePickerOptions(runs: readonly RunListItem[], query = ""): CaseOption[] {
  const terms = query.toLocaleLowerCase("ko-KR").split(/\s+/).filter(Boolean);
  return runs
    .map((run, index) => ({ run, index }))
    .sort((a, b) => timeOf(b.run) - timeOf(a.run) || a.index - b.index)
    .map(({ run }) => toCaseOption(run))
    .filter((option) => {
      if (terms.length === 0) return true;
      const hay = `${option.name} ${option.mode} ${option.runId}`.toLocaleLowerCase("ko-KR");
      return terms.every((term) => hay.includes(term));
    });
}

/** Next active row for ↑/↓ (wraps); -1 stays -1 when the list is empty. */
export function moveActiveIndex(current: number, delta: number, length: number): number {
  if (length === 0) return -1;
  if (current < 0) return delta > 0 ? 0 : length - 1;
  return (((current + delta) % length) + length) % length;
}
