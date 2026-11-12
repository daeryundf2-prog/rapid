import { QueryClientContext, useQuery } from "@tanstack/react-query";
import { type ReactElement, useContext, useEffect, useRef, useState } from "react";
import { announce } from "../a11y";
import { type CaseDetail, listCases } from "../api/cases";
import { getRunDashboard, type RunScope, type StepsSummary } from "../api/dashboard";
import {
  normalizeRunStatus,
  RETRYABLE_RUN_STATUSES,
  type RunEvidenceTimezone,
  runEvidenceZone,
  runStartedAt,
} from "../api/runs";
import type { RunWithProgress } from "../api/runsProgress";
import { runDisplayName } from "../app/collections";
import { CommandButton } from "../commands/CommandButton";
import { StatusBadge, statusLabel } from "../components/Badge";
import { ToneChip } from "../components/ToneChip";
import "../components/status.css";
import { serializeRoute } from "../router";
import { useRuns, useTimezone } from "../state/hooks";
import { isRunActive } from "../state/slices/runs";
import { useAppStore } from "../state/store";
import { evidenceZoneOption, tzOffsetLabel } from "../utils/time";
import { Slot } from "./slots";

const NOTICE_MS = 6000;

export function formatElapsed(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "";
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const mm = String(m).padStart(2, "0");
  const ss = String(s).padStart(2, "0");
  return h > 0 ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}

/** Heartbeat age after which a running run reads "응답 없음" (the server's `stale` threshold). */
export const STALE_HEARTBEAT_MS = 90_000;

const n = (value: number) => value.toLocaleString("ko-KR");

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

function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [active]);
  return now;
}

const pct = (value: number) => `${value.toLocaleString("ko-KR", { maximumFractionDigits: 1 })}%`;

/**
 * Outcome of a finished run for the status bar (T-174): "부분" when any measured scope axis is under
 * 100 % (partitions · allocated listing/content · deleted attempts · unallocated), a cap was reached,
 * the server flags the scope partial, or a step ended partial/incomplete; "완료" only when none of
 * that holds and no step failed. Axes the server did not measure (null) are not counted either way.
 * `unknown` = neither scope nor steps were sent (older server): the bar then shows the run status.
 */
export interface RunOutcome {
  kind: "complete" | "partial" | "unknown";
  failed: number;
  failedNames: string[];
  /** Why the run reads 부분 (the chip's tooltip). */
  reasons: string[];
}

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

/** The run line with its case/evidence names and (finished runs) the scope/steps outcome. */
function RunProgressQueried({ run }: { run: RunWithProgress }) {
  const active = isRunActive(run);
  const cases = useQuery({ queryKey: ["cases"], queryFn: listCases, retry: false });
  // Same key as the 접수 dashboard / tree: scope (T-023) and steps (T-021) of a finished run.
  const dashboard = useQuery({
    queryKey: ["run-dashboard", run.run_id],
    queryFn: () => getRunDashboard(run.run_id),
    enabled: !active,
    retry: false,
  });
  const outcome = dashboard.data ? runOutcome(dashboard.data.scope, dashboard.data.steps) : null;
  return (
    <RunProgress
      run={run}
      identity={runIdentityText(run, cases.data)}
      outcome={outcome}
      outcomePending={!active && dashboard.isPending}
    />
  );
}

function RunProgress({
  run,
  identity,
  outcome = null,
  outcomePending = false,
}: {
  run: RunWithProgress;
  identity?: string;
  outcome?: RunOutcome | null;
  outcomePending?: boolean;
}) {
  const active = isRunActive(run);
  const now = useNow(active);
  const started = Date.parse(runStartedAt(run) ?? "");
  const errors = run.progress?.error_count ?? 0;
  const planCounts = run.progress?.plan_counts;
  const planTotal = typeof planCounts?.tasks === "number" ? planCounts.tasks : 0;
  const total = planTotal || (run.progress?.total_count ?? 0);
  const done = planTotal
    ? (planCounts?.completed ?? 0) +
      (planCounts?.partial ?? 0) +
      (planCounts?.failed ?? 0) +
      (planCounts?.skipped ?? 0) +
      (planCounts?.cancelled ?? 0)
    : (run.progress?.completed_count ?? 0);
  const text = progressText(run);
  const stale = staleText(run, now);

  // Announce stage / status transitions only (not every poll).
  const stage = run.progress?.stage ?? "";
  const status = normalizeRunStatus(run.status);
  const name = identity || runDisplayName(run);
  const retryable = RETRYABLE_RUN_STATUSES.has(status);
  const announced = useRef<string | null>(null);
  useEffect(() => {
    const sentence = `런 ${name}: ${stage || statusLabel(status)}`;
    // Skip the first render (opening a case is not news); announce transitions only.
    if (announced.current !== null && announced.current !== sentence) announce(sentence);
    announced.current = sentence;
  }, [status, stage, name]);

  // A finished run's chip comes from its scope and steps (T-174): green 완료 only with every
  // measured axis at 100 % and no failed step; never 완료 · 오류 0 while the run is partial.
  const finishedOk = status === "completed";
  const known = outcome && outcome.kind !== "unknown" ? outcome : null;
  let chip: ReactElement;
  if (finishedOk && known?.kind === "complete") {
    chip = (
      <ToneChip tone="ok" testId="status-outcome">
        완료
      </ToneChip>
    );
  } else if (finishedOk && known?.kind === "partial") {
    chip = (
      <ToneChip tone="warn" testId="status-outcome" title={known.reasons.join(" · ") || undefined}>
        부분
      </ToneChip>
    );
  } else if (finishedOk && outcomePending) {
    chip = (
      <ToneChip tone="" testId="status-outcome">
        범위 확인 중
      </ToneChip>
    );
  } else {
    chip = <StatusBadge status={String(run.status)} />;
  }
  const failedSteps = known?.failed ?? 0;

  // "사건 · 증거 · 완료" / "… · 부분 · 실패 단계 2", then the run actions as their own group (visual-polish §0).
  return (
    <div className="status-run" data-testid="status-run">
      <span className="status-group">
        <span data-testid="status-run-name" title={`런 ID ${run.run_id}`}>
          {name}
        </span>
        <StatusSep />
        {chip}
        {failedSteps > 0 ? (
          <>
            <StatusSep />
            <span
              className="status-errors"
              data-testid="status-failed-steps"
              title={known?.failedNames.join(", ") || undefined}
            >
              실패 단계 {n(failedSteps)}
            </span>
          </>
        ) : null}
        {text ? (
          <>
            <StatusSep />
            <span className="status-text">{text}</span>
          </>
        ) : null}
        {active && total > 0 ? (
          <progress
            className="status-progress"
            max={total}
            value={Math.min(done, total)}
            aria-label={planTotal ? "태스크 진행률" : "provider 진행률"}
          />
        ) : null}
        {stale ? (
          <>
            <StatusSep />
            <span className="status-errors" data-testid="status-stale">
              {stale}
            </span>
          </>
        ) : null}
        {status === "interrupted" ? (
          <>
            <StatusSep />
            <span>서버 재시작</span>
          </>
        ) : null}
        {active && Number.isFinite(started) ? (
          <>
            <StatusSep />
            <span>{formatElapsed(now - started)} 경과</span>
          </>
        ) : null}
        {/* Once the outcome is known, "오류 0" is dropped (the chip and the failed-step count say it). */}
        {!known || errors > 0 ? (
          <>
            <StatusSep />
            <span className={errors > 0 ? "status-errors" : undefined}>오류 {errors}</span>
          </>
        ) : null}
      </span>
      {/* Run actions only when they apply (review #8): 취소 while running, 재시도 after a failure;
          an interrupted or cancelled run resumes (R4 V1). */}
      {active || retryable ? (
        <span className="status-group status-actions">
          {active ? (
            <>
              <a
                className="button ghost"
                href={serializeRoute({ runId: run.run_id, collection: "process" })}
                data-testid="run-plan-open"
              >
                진행 상세…
              </a>
              <CommandButton command="case.cancel" label="취소" variant="ghost" testId="run-cancel" />
            </>
          ) : null}
          {status === "interrupted" || status === "cancelled" ? (
            <CommandButton command="run.resume" label="이어서 실행" variant="ghost" testId="run-resume" />
          ) : null}
          {status === "failed" ? (
            <CommandButton command="case.retry" label="재시도" variant="ghost" testId="run-retry" />
          ) : null}
        </span>
      ) : null}
    </div>
  );
}

/** Visual separator between status-bar facts (not read out): a 1px × 14px rule (review #8). */
function StatusSep() {
  return <span className="status-sep" aria-hidden="true" />;
}

const TZ_OPTIONS: ReadonlyArray<[string, string]> = [
  ["utc", "UTC"],
  ["local", "브라우저 로컬"],
  ["Asia/Seoul", "서울 (Asia/Seoul)"],
  ["America/New_York", "뉴욕"],
  ["Europe/London", "런던"],
];

/**
 * Zone choices of the status bar: the evidence system's zone first when the run recorded one
 * (P6: "증거 시스템(KST −540)"), then the fixed list; the current choice is kept when unknown.
 */
export function timezoneOptions(
  evidence: RunEvidenceTimezone | null | undefined,
  current?: string,
): Array<[string, string]> {
  const options: Array<[string, string]> = [];
  const zone = evidenceZoneOption(evidence);
  if (zone) options.push([zone.value, zone.label]);
  for (const option of TZ_OPTIONS)
    if (!options.some(([value]) => value === option[0])) options.push([...option]);
  if (current && !options.some(([value]) => value === current)) options.unshift([current, current]);
  return options;
}

/** "시간대 UTC+09:00" with a select that changes the global display timezone (X4). */
export function TimezoneControl() {
  const { timezone, setTimezone } = useTimezone();
  const { currentRun } = useRuns();
  const options = timezoneOptions(runEvidenceZone(currentRun), timezone);
  return (
    <label className="status-tz" data-testid="status-tz">
      <span>시간대 {tzOffsetLabel(timezone)}</span>
      <select aria-label="표시 시간대" value={timezone} onChange={(event) => setTimezone(event.target.value)}>
        {options.map(([value, label]) => (
          <option key={value} value={value}>
            {label}
          </option>
        ))}
      </select>
    </label>
  );
}

/** "런 40건 · 케이스 1건" (C-G5); the case count only once known. */
export function runCountText(runCount: number, caseCount?: number | null): string {
  const runs = `런 ${n(runCount)}건`;
  return typeof caseCount === "number" ? `${runs} · 케이스 ${n(caseCount)}건` : runs;
}

function RunCaseCount({ runCount }: { runCount: number }) {
  const cases = useQuery({ queryKey: ["cases"], queryFn: listCases, retry: false });
  return <span data-testid="status-run-count">{runCountText(runCount, cases.data?.length)}</span>;
}

/** Bottom status bar (plan U8): run progress, cancel/retry, connection, last command notice. */
export function StatusBar() {
  const { runs, runsStatus, currentRun } = useRuns();
  const notice = useAppStore((s) => s.notice);
  const clearNotice = useAppStore((s) => s.clearNotice);
  const activeCount = runs.filter(isRunActive).length;
  // Runs and cases are different things (C-G5): "런 40건 · 케이스 1건" (cases need the query client).
  const queryClient = useContext(QueryClientContext);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(clearNotice, NOTICE_MS);
    return () => window.clearTimeout(timer);
  }, [notice, clearNotice]);

  return (
    <footer className="statusbar" data-testid="statusbar">
      {currentRun ? (
        queryClient ? (
          <RunProgressQueried run={currentRun} />
        ) : (
          <RunProgress run={currentRun} />
        )
      ) : queryClient ? (
        <RunCaseCount runCount={runs.length} />
      ) : (
        <span data-testid="status-run-count">{runCountText(runs.length)}</span>
      )}
      {activeCount > 0 && (!currentRun || !isRunActive(currentRun)) ? (
        <span>실행 중 런 {activeCount}건</span>
      ) : null}
      <Slot name="status-extra" />
      <span className="statusbar-spacer" />
      <TimezoneControl />
      <StatusSep />
      <span className="status-connection-wrap">
        <span
          className={`status-dot ${runsStatus === "error" ? "danger" : runsStatus === "loading" ? "" : "ok"}`}
          aria-hidden="true"
        />
        <span className={`status-connection ${runsStatus}`} data-testid="status-connection">
          {runsStatus === "error" ? "연결 끊김" : runsStatus === "loading" ? "연결 중…" : "연결됨"}
        </span>
      </span>
    </footer>
  );
}
