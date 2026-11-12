import type { CaseDetail } from "../api/cases";
import type { RunScope, StepsSummary } from "../api/dashboard";
import type { RunWithProgress } from "../api/runsProgress";
import { runDisplayName } from "../app/collections";
import { isRunActive } from "../state/slices/runs";

/** Status-bar text and outcome derivation (pure; split out of StatusBar.tsx). */

const n = (value: number) => value.toLocaleString("ko-KR");

/**
 * The console's one duration format (run rows, steps, status bar, 접수 cards): "MM:SS", and
 * "HH:MM:SS" from an hour on — every part two digits, so "02:23:02" and "01:06" read alike
 * (verify WB-10: the hour was unpadded, "2:23:02"). Whole seconds, floored.
 */
export function formatElapsed(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "";
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (value: number) => String(value).padStart(2, "0");
  return h > 0 ? `${pad(h)}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

/** Heartbeat age after which a running run reads "응답 없음" (the server's `stale` threshold). */
export const STALE_HEARTBEAT_MS = 90_000;

/**
 * Run-plan progress (R4 V1): "그룹 7/23 · 태스크 19/36 · 실행 중: 이벤트 로그(12,340행) · 건너뜀 3".
 * `groups` / `tasks` of `plan_counts` are totals; the rest are task counts. The finished-group
 * count is shown only when the server sends one (`groups_done`).
 */
export function planProgressText(progress: RunWithProgress["progress"]): string {
  const counts = progress?.plan_counts;
  if (!counts || typeof counts.tasks !== "number") return "";
  const parts: string[] = [];
  if (typeof counts.groups === "number") {
    parts.push(
      typeof counts.groups_done === "number"
        ? `그룹 ${n(counts.groups_done)}/${n(counts.groups)}`
        : `그룹 ${n(counts.groups)}`,
    );
  }
  const finished =
    (counts.completed ?? 0) +
    (counts.partial ?? 0) +
    (counts.failed ?? 0) +
    (counts.skipped ?? 0) +
    (counts.cancelled ?? 0);
  parts.push(`태스크 ${n(finished)}/${n(counts.tasks)}`);
  const current = (progress?.current ?? []).slice(0, 3);
  if (current.length) {
    parts.push(
      `실행 중: ${current
        .map((task) => {
          const label = task.label || task.task;
          return typeof task.rows_so_far === "number" ? `${label}(${n(task.rows_so_far)}행)` : label;
        })
        .join(", ")}`,
    );
  } else if (progress?.running?.length) {
    parts.push(
      `실행 중: ${progress.running.slice(0, 3).join(", ")}${progress.running.length > 3 ? " 외" : ""}`,
    );
  }
  if (counts.skipped) parts.push(`건너뜀 ${n(counts.skipped)}`);
  if (counts.cancelled) parts.push(`취소 ${n(counts.cancelled)}`);
  if (counts.failed) parts.push(`실패 ${n(counts.failed)}`);
  return parts.join(" · ");
}

/**
 * "응답 없음 · 마지막 신호 3분 전" when an active run's heartbeat stopped (server `stale`, or the
 * heartbeat is older than 90 s); "" otherwise.
 */
export function staleText(run: RunWithProgress, now: number): string {
  if (!isRunActive(run)) return "";
  const beat = run.progress?.heartbeat_at ? Date.parse(run.progress.heartbeat_at) : Number.NaN;
  const age = Number.isFinite(beat) ? now - beat : Number.NaN;
  const stale = run.progress?.stale === true || (Number.isFinite(age) && age > STALE_HEARTBEAT_MS);
  if (!stale) return "";
  if (!Number.isFinite(age)) return "응답 없음";
  const minutes = Math.max(1, Math.floor(age / 60_000));
  return `응답 없음 · 마지막 신호 ${n(minutes)}분 전`;
}

/** Plain-language progress line for a run (also the live-region sentence). */
export function progressText(run: RunWithProgress): string {
  const p = run.progress;
  const plan = planProgressText(p);
  if (plan) return plan;
  const parts: string[] = [];
  if (p?.stage) parts.push(p.stage);
  if (typeof p?.total_count === "number" && p.total_count > 0) {
    parts.push(`provider ${p.completed_count ?? 0}/${p.total_count}`);
  }
  if (p?.running?.length)
    parts.push(`실행 중: ${p.running.slice(0, 3).join(", ")}${p.running.length > 3 ? " 외" : ""}`);
  return parts.join(" · ");
}

const pct = (value: number) => `${value.toLocaleString("ko-KR", { maximumFractionDigits: 1 })}%`;

/**
 * Outcome of a finished run for the status bar (T-174): "부분" when any measured scope axis is under
 * 100 % (partitions · allocated listing/content · deleted attempts · unallocated), a cap was reached,
 * the server flags the scope partial, or a step ended partial/incomplete; "완료" only when none of
 * that holds and no step failed. Axes the server did not measure (null) are not counted either way.
 * `unknown` = neither scope nor steps were sent (older server): the bar then shows the neutral
 * OUTCOME_UNKNOWN chip, as it does when the dashboard request fails.
 */
export interface RunOutcome {
  kind: "complete" | "partial" | "unknown";
  failed: number;
  failedNames: string[];
  /** Why the run reads 부분 (the chip's tooltip). */
  reasons: string[];
}

/** Neutral chip of a finished run whose outcome could not be read (dashboard failed, older server). */
export const OUTCOME_UNKNOWN = "범위 확인 불가";

export function runOutcome(
  scope: RunScope | null | undefined,
  steps: StepsSummary | null | undefined,
): RunOutcome {
  const scoped = scope && scope.basis !== "unavailable" ? scope : null;
  const failed = steps?.failed ?? 0;
  const failedNames = steps?.failed_names ?? [];
  if (!scoped && !steps) return { kind: "unknown", failed, failedNames, reasons: [] };
  const reasons: string[] = [];
  if (scoped) {
    const { partitions, allocated, deleted, unallocated } = scoped;
    if (
      typeof partitions.supported === "number" &&
      typeof partitions.processed === "number" &&
      partitions.processed < partitions.supported
    )
      reasons.push(`파티션 ${n(partitions.processed)}/${n(partitions.supported)}`);
    const axes: Array<[string, number | null | undefined]> = [
      ["할당 목록", allocated.listed_pct],
      ["할당 내용", allocated.content_pct],
      ["삭제 시도", deleted.attempted_pct],
      ["비할당", unallocated.scanned_pct],
    ];
    for (const [label, value] of axes)
      if (typeof value === "number" && value < 100) reasons.push(`${label} ${pct(value)}`);
    if (scoped.caps.some((cap) => cap.reached !== false)) reasons.push("처리 상한 도달");
    if (scoped.partial === true && reasons.length === 0) reasons.push("처리 범위 일부");
  }
  if (steps) {
    if (steps.partial > 0) reasons.push(`일부 완료 단계 ${n(steps.partial)}`);
    if (steps.incomplete > 0) reasons.push(`미완료 단계 ${n(steps.incomplete)}`);
  }
  const kind = reasons.length > 0 || failed > 0 ? "partial" : "complete";
  return { kind, failed, failedNames, reasons };
}

/**
 * Case · evidence display names of a run (T-174) instead of "런 <id>": "2026-1 사건 · 노트북 E01"
 * from the case list (the evidence the run belongs to), else the evidence folder/file name.
 */
export function runIdentityText(run: RunWithProgress, cases?: readonly CaseDetail[] | null): string {
  for (const item of cases ?? []) {
    const evidence = item.evidence.find((ev) => ev.runs.some((brief) => brief.run_id === run.run_id));
    if (!evidence) continue;
    const caseName = item.name || item.case_number;
    const evidenceName = evidence.display_name || evidence.evidence_number || runDisplayName(run);
    return caseName ? `${caseName} · ${evidenceName}` : evidenceName;
  }
  return runDisplayName(run);
}
