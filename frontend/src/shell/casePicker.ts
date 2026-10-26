/**
 * Run picker model (review #5, R7 C-G5 · C-L1): the rows of the top bar's run combobox — newest
 * representative start first, narrowed by the search text — and the wrap-around keyboard move.
 * The rows are runs (a case groups runs; the dialog "케이스 열기" shows that tree).
 */

import { type RunListItem, runStartedMs } from "../api/runs";
import { RUN_MODE_LABEL, runDisplayName } from "../app/collections";
import { statusTone } from "../components/Badge";
import { runChipText, runDurationText, runStartText } from "../features/case/runTime";
import { formatRunTime, parseInstant } from "../utils/time";

export interface CaseOption {
  runId: string;
  /** Evidence folder name (13px/500 first line). */
  name: string;
  /** Investigation mode label ("문서·부정 조사"), or "모드 없음". */
  mode: string;
  /** Representative start "2026-10-13 10:07" in the display zone ("가져옴 …" = import time), or "". */
  date: string;
  /** 소요 "34:09", "—" when unknown (an imported run without processing times). */
  duration: string;
  /** Run chip `모드 · 시작 시각 · 소요 · id8` (C-L1). */
  chip: string;
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

/** ISO time → "YYYY-MM-DD HH:mm" in `timezone` ("" when missing or unparsable) — `formatRunTime`. */
export function shortDateTime(iso: string | undefined | null, timezone = "local"): string {
  if (!iso || !parseInstant(iso)) return "";
  return formatRunTime(iso, timezone);
}

export function toCaseOption(run: RunListItem, timezone = "local", now: number = Date.now()): CaseOption {
  const mode = run.request?.mode ?? "";
  const tone = statusTone(run.status);
  return {
    runId: run.run_id,
    name: runDisplayName(run),
    mode: RUN_MODE_LABEL[mode] ?? (mode || "모드 없음"),
    date: runStartText(run, timezone),
    duration: runDurationText(run, now),
    chip: runChipText(run, timezone, now),
    status: run.status,
    tone: tone === "muted" ? "" : tone,
  };
}

/**
 * Picker rows: newest representative start first (stable for equal times), filtered by every
 * whitespace-separated term of `query` against the name, the mode label and the run id.
 */
export function casePickerOptions(
  runs: readonly RunListItem[],
  query = "",
  timezone = "local",
): CaseOption[] {
  const terms = query.toLocaleLowerCase("ko-KR").split(/\s+/).filter(Boolean);
  const now = Date.now();
  return runs
    .map((run, index) => ({ run, index }))
    .sort((a, b) => runStartedMs(b.run) - runStartedMs(a.run) || a.index - b.index)
    .map(({ run }) => toCaseOption(run, timezone, now))
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
