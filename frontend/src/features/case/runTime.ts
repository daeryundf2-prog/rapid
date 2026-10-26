/**
 * Run identity on the case screens (R7 L1, C-G3 · C-L1): one start time, one duration and one
 * chip text per run — 랜딩 "최근 런", 케이스 열기, the top-bar picker and the 처리 run list read
 * these, so the same run prints the same string everywhere.
 */

import {
  isImportedRun,
  type RunTimeSource,
  runCompletedAt,
  runDurationMs,
  runStartedAt,
  runTimeIsImport,
} from "../../api/runs";
import { RUN_MODE_LABEL } from "../../app/collections";
import { formatElapsed } from "../../shell/StatusBar";
import { formatRunTime } from "../../utils/time";

/** "2026-10-17 20:18" (or "가져옴 2026-10-17 08:52" when only the import time is known); "" when none. */
export function runStartText(run: RunTimeSource, timezone: string): string {
  const started = runStartedAt(run);
  if (!started) return "";
  const text = formatRunTime(started, timezone);
  return runTimeIsImport(run) ? `가져옴 ${text}` : text;
}

/** 소요 "34:09" (h:mm:ss / mm:ss), "—" when a bound is missing (an imported run without times). */
export function runDurationText(run: RunTimeSource, now: number = Date.now()): string {
  const ms = runDurationMs(run, now);
  return ms === null ? "—" : formatElapsed(ms) || "—";
}

/** Mode label ("문서·부정 조사", "빠른 선별"); the raw id only for an unknown mode. */
export function runModeText(run: RunTimeSource): string {
  const mode = String(run.request?.mode ?? "");
  return RUN_MODE_LABEL[mode] ?? mode;
}

/** Run chip `모드 · 시작 시각 · 소요 · id8` (C-L1); empty parts dropped. */
export function runChipText(run: RunTimeSource, timezone: string, now: number = Date.now()): string {
  const duration = runDurationText(run, now);
  return [
    runModeText(run),
    runStartText(run, timezone),
    duration === "—" ? "" : `소요 ${duration}`,
    run.run_id.slice(0, 8),
  ]
    .filter(Boolean)
    .join(" · ");
}

/** Tooltip: evidence path, start → end, the import time of an imported run, the full run id. */
export function runTimeTooltip(run: RunTimeSource, timezone: string): string {
  const started = runStartedAt(run);
  const completed = runCompletedAt(run);
  const lines = [run.request?.root ?? ""];
  if (started && !runTimeIsImport(run))
    lines.push(
      `시작 ${formatRunTime(started, timezone)}${completed ? ` → 완료 ${formatRunTime(completed, timezone)}` : ""}`,
    );
  const importedAt = run.run_times?.imported_at ?? (isImportedRun(run) ? run.created_at : null);
  if (importedAt) lines.push(`가져옴 ${formatRunTime(importedAt, timezone)} (처리 시각 아님)`);
  lines.push(`런 ID ${run.run_id}`);
  return lines.filter(Boolean).join("\n");
}
