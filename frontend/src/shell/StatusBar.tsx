import { useEffect, useRef, useState } from "react";
import { announce } from "../a11y";
import type { RunWithProgress } from "../api/runsProgress";
import { runDisplayName } from "../app/collections";
import { CommandButton } from "../commands/CommandButton";
import { StatusBadge, statusLabel } from "../components/Badge";
import "../components/status.css";
import { useRuns, useTimezone } from "../state/hooks";
import { isRunActive } from "../state/slices/runs";
import { useAppStore } from "../state/store";
import { tzOffsetLabel } from "../utils/time";

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

/** Plain-language progress line for a run (also the live-region sentence). */
export function progressText(run: RunWithProgress): string {
  const p = run.progress;
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

function RunProgress({ run }: { run: RunWithProgress }) {
  const active = isRunActive(run);
  const now = useNow(active);
  const started = run.created_at ? Date.parse(run.created_at) : Number.NaN;
  const errors = run.progress?.error_count ?? 0;
  const total = run.progress?.total_count ?? 0;
  const done = run.progress?.completed_count ?? 0;
  const text = progressText(run);

  // Announce stage / status transitions only (not every poll).
  const stage = run.progress?.stage ?? "";
  const status = String(run.status ?? "");
  const name = runDisplayName(run);
  const announced = useRef<string | null>(null);
  useEffect(() => {
    const sentence = `런 ${name}: ${stage || statusLabel(status)}`;
    // Skip the first render (opening a case is not news); announce transitions only.
    if (announced.current !== null && announced.current !== sentence) announce(sentence);
    announced.current = sentence;
  }, [status, stage, name]);

  return (
    <div className="status-run" data-testid="status-run">
      <span className="mono" title={run.run_id}>
        런 {run.run_id.slice(0, 8)}…
      </span>
      <StatusBadge status={String(run.status)} />
      {text ? <span>{text}</span> : null}
      {active && total > 0 ? (
        <progress className="status-progress" max={total} value={done} aria-label="provider 진행률" />
      ) : null}
      {active && Number.isFinite(started) ? <span>{formatElapsed(now - started)} 경과</span> : null}
      <span className={errors > 0 ? "status-errors" : undefined}>오류 {errors}</span>
      <CommandButton command="case.cancel" label="취소" variant="ghost" testId="run-cancel" />
      <CommandButton command="case.retry" label="재시도" variant="ghost" testId="run-retry" />
    </div>
  );
}

const TZ_OPTIONS: ReadonlyArray<[string, string]> = [
  ["utc", "UTC"],
  ["local", "브라우저 로컬"],
  ["Asia/Seoul", "서울 (Asia/Seoul)"],
  ["America/New_York", "뉴욕"],
  ["Europe/London", "런던"],
];

/** "시간대 UTC+09:00" with a select that changes the global display timezone (X4). */
export function TimezoneControl() {
  const { timezone, setTimezone } = useTimezone();
  const known = TZ_OPTIONS.some(([value]) => value === timezone);
  return (
    <label className="status-tz" data-testid="status-tz">
      <span>시간대 {tzOffsetLabel(timezone)}</span>
      <select aria-label="표시 시간대" value={timezone} onChange={(event) => setTimezone(event.target.value)}>
        {known ? null : <option value={timezone}>{timezone}</option>}
        {TZ_OPTIONS.map(([value, label]) => (
          <option key={value} value={value}>
            {label}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Bottom status bar (plan U8): run progress, cancel/retry, connection, last command notice. */
export function StatusBar() {
  const { runs, runsStatus, currentRun } = useRuns();
  const notice = useAppStore((s) => s.notice);
  const clearNotice = useAppStore((s) => s.clearNotice);
  const activeCount = runs.filter(isRunActive).length;

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(clearNotice, NOTICE_MS);
    return () => window.clearTimeout(timer);
  }, [notice, clearNotice]);

  return (
    <footer className="statusbar" data-testid="statusbar">
      {currentRun ? (
        <RunProgress run={currentRun} />
      ) : (
        <span data-testid="status-run-count">케이스 {runs.length}건</span>
      )}
      {activeCount > 0 && (!currentRun || !isRunActive(currentRun)) ? (
        <span>실행 중 런 {activeCount}건</span>
      ) : null}
      <span className="statusbar-spacer" />
      {notice ? (
        <span className={`status-notice ${notice.tone}`} data-testid="status-notice">
          {notice.text}
        </span>
      ) : null}
      <TimezoneControl />
      <span className={`status-connection ${runsStatus}`} data-testid="status-connection">
        {runsStatus === "error" ? "연결 끊김" : runsStatus === "loading" ? "연결 중…" : "연결됨"}
      </span>
    </footer>
  );
}
