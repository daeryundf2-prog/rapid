import { QueryClientContext, useQuery } from "@tanstack/react-query";
import { type ReactElement, useContext, useEffect, useRef, useState } from "react";
import { announce } from "../a11y";
import { listCases } from "../api/cases";
import { getRunDashboard } from "../api/dashboard";
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
import {
  formatElapsed,
  progressText,
  type RunOutcome,
  runIdentityText,
  runOutcome,
  staleText,
} from "./statusBarOutcome";

const NOTICE_MS = 6000;

const n = (value: number) => value.toLocaleString("ko-KR");

function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [active]);
  return now;
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
