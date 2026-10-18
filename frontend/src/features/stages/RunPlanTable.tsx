/**
 * 처리 계획표 (R4 V1, plan run-model-p2 §3.7 U-P2-1/2): the run's groups → tasks as a treegrid.
 * Group rows: progress bar + "3/5 태스크", state, row counts, duration and one × button (건너뛰기
 * while every remaining task is queued, 취소 while one runs). Task rows: state, rows (live
 * `rows_so_far` and a ticking elapsed clock while running), duration, message, the reason of a
 * partial / cancelled / skipped task, and their own × button. "모두 취소" and "지금까지로 마치기"
 * sit above the table. Keyboard: ↑/↓ move, →/← expand / collapse (or go to child / parent),
 * Enter / Space toggle, Home / End.
 */

import { useQueryClient } from "@tanstack/react-query";
import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import { announce, DisabledReason } from "../../a11y";
import { ApiError } from "../../api/client";
import {
  controlRunPlan,
  FINISHED_TASK_STATUSES,
  isPlanPolling,
  type PlanControlAction,
  type PlanGroup,
  type PlanTarget,
  type PlanTask,
  type RunPlan,
  runPlanQueryKey,
} from "../../api/runPlan";
import { normalizeRunStatus } from "../../api/runs";
import { RUNS_QUERY_KEY } from "../../api/runsProgress";
import { FINISHED_TASK_REASON, NO_QUEUED_REASON, NOT_RUNNING_REASON } from "../../commands/builtin";
import { CANCEL_ALL_CONFIRM, confirmAction } from "../../commands/reasons";
import { StatusBadge, statusLabel } from "../../components/Badge";
import { Icon } from "../../icons";
import { formatElapsed } from "../../shell/StatusBar";
import { useTimezone } from "../../state/hooks";
import { useAppStore } from "../../state/store";
import { formatTimestamp } from "../../utils/time";
import { formatCount } from "../grid/gridUtils";
import { useNow } from "./useNow";

/** A required group / task (준비 · 지문 · 보고서): never skipped or cancelled alone. */
export const REQUIRED_TASK_REASON = "필수 단계는 건너뛰거나 따로 취소할 수 없습니다";

/** Completed rows of a group / task count (일부 완료 included): the progress numerator. */
export function doneCount(counts: PlanGroup["counts"]): number {
  return counts.completed + counts.partial;
}

/** "그룹 23 / 태스크 36 · 시작 … · 경과 … · 완료 a · 부분 b · 건너뜀 c · 취소 d · 실패 e". */
export function planSummaryText(plan: RunPlan, opts: { started?: string; elapsed?: string } = {}): string {
  const tasks = plan.counts.tasks;
  return [
    `그룹 ${formatCount(plan.counts.groups.total || plan.groups.length)} / 태스크 ${formatCount(tasks.total)}`,
    ...(opts.started ? [`시작 ${opts.started}`] : []),
    ...(opts.elapsed ? [`경과 ${opts.elapsed}`] : []),
    `완료 ${formatCount(tasks.completed)}`,
    `부분 ${formatCount(tasks.partial)}`,
    `건너뜀 ${formatCount(tasks.skipped)}`,
    `취소 ${formatCount(tasks.cancelled)}`,
    `실패 ${formatCount(tasks.failed)}`,
  ].join(" · ");
}

/** "이벤트 로그, 실행 중, 3/5 태스크" — a group row's accessible name. */
export function groupAriaLabel(group: PlanGroup): string {
  return `${group.label}, ${statusLabel(group.status)}, ${doneCount(group.counts)}/${group.counts.total} 태스크`;
}

/** What a group's × does now: cancel while a task runs, skip while the rest is queued, else nothing. */
export function groupAction(group: PlanGroup): "cancel" | "skip" | null {
  if (group.counts.running > 0) return "cancel";
  if (group.counts.queued > 0) return "skip";
  return null;
}

export function taskAction(task: PlanTask): "cancel" | "skip" | null {
  if (task.status === "running") return "cancel";
  if (task.status === "queued") return "skip";
  return null;
}

/** Disabled reason of a row's × (undefined = it can run). */
export function rowActionReason(
  runActive: boolean,
  action: "cancel" | "skip" | null,
  skippable: boolean | undefined,
): string | undefined {
  if (!runActive) return NOT_RUNNING_REASON;
  if (!action) return FINISHED_TASK_REASON;
  if (skippable === false) return REQUIRED_TASK_REASON;
  return undefined;
}

/** Reason text of a task ("검사관 요청 · web"), shown for partial / cancelled / skipped tasks. */
export function taskReasonText(task: PlanTask): string {
  const reason = task.reason?.trim() ?? "";
  const actor = task.requested_by?.actor ? `요청: ${task.requested_by.actor}` : "";
  return [reason, actor].filter(Boolean).join(" · ");
}

function durationText(ms: number | null | undefined): string {
  return typeof ms === "number" && ms >= 0 ? formatElapsed(ms) : "";
}

function startedMs(value: string | null | undefined): number {
  return value ? Date.parse(value) : Number.NaN;
}

type RowRef = { kind: "group"; group: PlanGroup } | { kind: "task"; group: PlanGroup; task: PlanTask };

const rowKey = (row: RowRef) => (row.kind === "group" ? `g:${row.group.id}` : `t:${row.task.id}`);

/**
 * Polite announcements of finished groups (one sentence per poll: "이벤트 로그 그룹 완료 ·
 * 48,120건") and refreshes of what they feed: when the completed task count grows, the run tree
 * and the artifact pages refetch. The first plan of a run is history, not news.
 */
export function useRunPlanTransitions(runId: string | null, plan: RunPlan | undefined): void {
  const queryClient = useQueryClient();
  const previous = useRef<{ runId: string | null; groups: Map<string, string>; done: number } | null>(null);
  useEffect(() => {
    if (!plan || !runId) return;
    const before = previous.current?.runId === runId ? previous.current : null;
    const done = plan.counts.tasks.completed + plan.counts.tasks.partial;
    previous.current = { runId, groups: new Map(plan.groups.map((g) => [g.id, String(g.status)])), done };
    if (!before) return;
    const sentences: string[] = [];
    let failed = false;
    for (const group of plan.groups) {
      const old = before.groups.get(group.id);
      if (!old || FINISHED_TASK_STATUSES.has(old) || !FINISHED_TASK_STATUSES.has(String(group.status)))
        continue;
      const rows =
        typeof group.artifact_count === "number" &&
        (group.status === "completed" || group.status === "partial")
          ? ` · ${formatCount(group.artifact_count)}건`
          : "";
      sentences.push(`${group.label} 그룹 ${statusLabel(String(group.status))}${rows}`);
      if (group.status === "failed") failed = true;
    }
    if (sentences.length) announce(sentences.join(", "), { politeness: failed ? "assertive" : "polite" });
    if (done > before.done) {
      void queryClient.invalidateQueries({ queryKey: ["run-tree", runId] });
      void queryClient.invalidateQueries({ queryKey: ["collection", runId, "artifacts"] });
    }
  }, [runId, plan, queryClient]);
}

function errorText(error: unknown): string {
  return error instanceof ApiError || error instanceof Error ? error.message : String(error);
}

export function RunPlanTable({
  runId,
  plan,
  controls = true,
}: {
  runId: string;
  plan: RunPlan;
  /** Show "모두 취소" / "지금까지로 마치기" above the table (the 처리 run card carries its own). */
  controls?: boolean;
}) {
  const queryClient = useQueryClient();
  const { timezone } = useTimezone();
  const runStatus = normalizeRunStatus(plan.run_status);
  const runActive = isPlanPolling(runStatus);
  const now = useNow(runActive);
  const [expanded, setExpanded] = useState<Set<string>>(
    () => new Set(plan.groups.filter((g) => g.status === "running").map((g) => g.id)),
  );
  const [focusedKey, setFocusedKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const rowRefs = useRef(new Map<string, HTMLTableRowElement>());
  useRunPlanTransitions(runId, plan);

  const rows = useMemo(() => {
    const out: RowRef[] = [];
    for (const group of plan.groups) {
      out.push({ kind: "group", group });
      if (expanded.has(group.id)) for (const task of group.tasks) out.push({ kind: "task", group, task });
    }
    return out;
  }, [plan.groups, expanded]);
  const tabStop = rows.some((row) => rowKey(row) === focusedKey)
    ? focusedKey
    : rows[0]
      ? rowKey(rows[0])
      : null;

  const started = plan.started_at ? formatTimestamp(plan.started_at, timezone, { precision: "minute" }) : "";
  const startMs = startedMs(plan.started_at);
  const elapsedMs = runActive && Number.isFinite(startMs) ? now - startMs : (plan.elapsed_ms ?? Number.NaN);
  const summary = planSummaryText(plan, { started, elapsed: durationText(elapsedMs) });
  const queued = plan.counts.tasks.queued;

  const send = async (action: PlanControlAction, targets: PlanTarget[] | undefined, what: string) => {
    if (action === "cancel_all" && !confirmAction(CANCEL_ALL_CONFIRM)) return;
    setBusy(true);
    try {
      // An in-flight plan poll that resolves after the reply would put the old plan back.
      await queryClient.cancelQueries({ queryKey: runPlanQueryKey(runId) });
      const result = await controlRunPlan(runId, action, targets);
      await queryClient.cancelQueries({ queryKey: runPlanQueryKey(runId) });
      queryClient.setQueryData(runPlanQueryKey(runId), result.plan);
      void queryClient.invalidateQueries({ queryKey: RUNS_QUERY_KEY });
      if (result.rejected.length) {
        const message = `${what} 거부: ${result.rejected.map((item) => item.reason).join(" · ")}`;
        useAppStore.getState().showNotice(message, "error");
        announce(message, { politeness: "assertive" });
      } else {
        announce(`${what} 요청을 보냈습니다`);
      }
    } catch (error) {
      const message = `${what} 실패: ${errorText(error)}`;
      useAppStore.getState().showNotice(message, "error");
      announce(message, { politeness: "assertive" });
    } finally {
      setBusy(false);
    }
  };

  const toggle = (groupId: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(groupId)) next.delete(groupId);
      else next.add(groupId);
      return next;
    });

  const focusRow = (key: string) => {
    setFocusedKey(key);
    rowRefs.current.get(key)?.focus();
  };

  /** The row's × button (out of the tab order; → from the row reaches it, ← goes back). */
  const focusRowAction = (key: string): boolean => {
    const button = rowRefs.current.get(key)?.querySelector<HTMLButtonElement>("button.run-plan-x");
    if (!button) return false;
    button.focus();
    return true;
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTableElement>) => {
    const target = event.target as HTMLElement;
    const actionOf = target.dataset.actionFor;
    if (actionOf) {
      // On a row's × button: ← / Esc back to the row, ↑ / ↓ to the neighbouring rows.
      const at = rows.findIndex((row) => rowKey(row) === actionOf);
      let moved: RowRef | undefined;
      if (event.key === "ArrowLeft" || event.key === "Escape") moved = rows[at];
      else if (event.key === "ArrowDown") moved = rows[at + 1];
      else if (event.key === "ArrowUp") moved = rows[at - 1];
      else return;
      if (moved) focusRow(rowKey(moved));
      event.preventDefault();
      return;
    }
    if (!target.dataset.rowKey) return;
    const key = target.dataset.rowKey ?? "";
    const index = rows.findIndex((row) => rowKey(row) === key);
    const row = rows[index];
    if (!row) return;
    let handled = true;
    switch (event.key) {
      case "ArrowDown": {
        const next = rows[index + 1];
        if (next) focusRow(rowKey(next));
        break;
      }
      case "ArrowUp": {
        const prev = rows[index - 1];
        if (prev) focusRow(rowKey(prev));
        break;
      }
      case "Home": {
        const first = rows[0];
        if (first) focusRow(rowKey(first));
        break;
      }
      case "End": {
        const last = rows[rows.length - 1];
        if (last) focusRow(rowKey(last));
        break;
      }
      case "ArrowRight":
        if (row.kind === "group") {
          if (!expanded.has(row.group.id) && row.group.tasks.length) toggle(row.group.id);
          else if (row.group.tasks[0]) focusRow(`t:${row.group.tasks[0].id}`);
          else focusRowAction(key);
        } else focusRowAction(key);
        break;
      case "ArrowLeft":
        if (row.kind === "group") {
          if (expanded.has(row.group.id)) toggle(row.group.id);
        } else focusRow(`g:${row.group.id}`);
        break;
      case "Enter":
      case " ":
        if (row.kind === "group") toggle(row.group.id);
        else handled = false;
        break;
      default:
        handled = false;
    }
    if (handled) event.preventDefault();
  };

  const cancelAllReason = runActive ? undefined : NOT_RUNNING_REASON;
  const finishReason = !runActive ? NOT_RUNNING_REASON : queued === 0 ? NO_QUEUED_REASON : undefined;

  return (
    <section className="stage-section process-plan run-plan" aria-labelledby="run-plan-title">
      <div className="process-plan-head">
        <h3 id="run-plan-title">처리 계획</h3>
        <p className="process-plan-tally" data-testid="run-plan-summary">
          {summary}
        </p>
      </div>
      {plan.stale ? (
        <p className="run-plan-stale" data-testid="run-plan-stale">
          응답 없음 · 런 프로세스의 신호가 90초 넘게 없습니다
        </p>
      ) : null}
      {controls ? (
        <div className="analysis-actions run-plan-controls">
          <DisabledReason reason={busy ? "요청을 보내는 중입니다" : cancelAllReason}>
            <button
              type="button"
              className="button"
              data-testid="run-plan-cancel-all"
              onClick={() => void send("cancel_all", undefined, "모두 취소")}
            >
              <Icon name="stop" />
              <span>모두 취소</span>
            </button>
          </DisabledReason>
          <DisabledReason reason={busy ? "요청을 보내는 중입니다" : finishReason}>
            <button
              type="button"
              className="button"
              data-testid="run-plan-finish"
              onClick={() => void send("finish", undefined, "지금까지로 마치기")}
            >
              <Icon name="check" />
              <span>지금까지로 마치기</span>
            </button>
          </DisabledReason>
        </div>
      ) : null}
      <div className="process-plan-wrap">
        <table
          // biome-ignore lint/a11y/noNoninteractiveElementToInteractiveRole: a table is the treegrid container (rows expand)
          role="treegrid"
          className="analysis-history process-plan-table run-plan-table"
          aria-label="처리 계획표"
          onKeyDown={onKeyDown}
        >
          <thead>
            <tr>
              <th scope="col">그룹 · 태스크</th>
              <th scope="col">상태</th>
              <th scope="col">진행</th>
              <th scope="col" className="is-right">
                건수
              </th>
              <th scope="col" className="is-right">
                소요
              </th>
              <th scope="col">비고</th>
              <th scope="col">
                <span className="visually-hidden">동작</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const key = rowKey(row);
              const common = {
                ref: (el: HTMLTableRowElement | null) => {
                  if (el) rowRefs.current.set(key, el);
                  else rowRefs.current.delete(key);
                },
                "data-row-key": key,
                tabIndex: key === tabStop ? 0 : -1,
                onFocus: () => setFocusedKey(key),
              };
              if (row.kind === "group") {
                const group = row.group;
                const open = expanded.has(group.id);
                const action = groupAction(group);
                const reason = busy
                  ? "요청을 보내는 중입니다"
                  : rowActionReason(runActive, action, group.skippable);
                const verb = action === "skip" ? "건너뛰기" : "취소";
                const done = doneCount(group.counts);
                return (
                  <tr
                    key={key}
                    {...common}
                    aria-level={1}
                    aria-expanded={group.tasks.length ? open : undefined}
                    aria-label={groupAriaLabel(group)}
                    className="run-plan-group"
                    data-status={group.status}
                    data-testid={`run-plan-group-${group.id}`}
                  >
                    <td>
                      <button
                        type="button"
                        className="run-plan-twisty"
                        tabIndex={-1}
                        aria-label={`${group.label} ${open ? "접기" : "펼치기"}`}
                        onClick={() => toggle(group.id)}
                      >
                        <Icon name={open ? "chevron-down" : "chevron-right"} />
                      </button>
                      <span className="run-plan-label">{group.label}</span>
                    </td>
                    <td>
                      <StatusBadge status={String(group.status)} />
                    </td>
                    <td className="run-plan-progress">
                      <progress
                        className="status-progress"
                        max={Math.max(1, group.counts.total)}
                        value={Math.min(done, group.counts.total)}
                        aria-label={`${group.label} 진행률`}
                      />
                      <span>{`${done}/${group.counts.total} 태스크`}</span>
                    </td>
                    <td className="is-right">
                      {typeof group.artifact_count === "number"
                        ? `${formatCount(group.artifact_count)}건`
                        : "—"}
                    </td>
                    <td className="is-right">{durationText(group.duration_ms) || "—"}</td>
                    <td className="process-plan-note">
                      {group.counts.skipped ? `건너뜀 ${group.counts.skipped}` : ""}
                      {group.counts.cancelled
                        ? `${group.counts.skipped ? " · " : ""}취소 ${group.counts.cancelled}`
                        : ""}
                    </td>
                    <td>
                      <DisabledReason reason={reason}>
                        <button
                          type="button"
                          className="icon-btn run-plan-x"
                          aria-label={`${group.label} 그룹 ${verb}`}
                          tabIndex={-1}
                          data-action-for={key}
                          data-action={action ?? "none"}
                          onClick={() => {
                            if (!action) return;
                            void send(action, [{ group: group.id }], `${group.label} 그룹 ${verb}`);
                          }}
                        >
                          <Icon name="close" />
                        </button>
                      </DisabledReason>
                    </td>
                  </tr>
                );
              }
              const task = row.task;
              const action = taskAction(task);
              const reason = busy
                ? "요청을 보내는 중입니다"
                : rowActionReason(runActive, action, task.skippable);
              const verb = action === "skip" ? "건너뛰기" : "취소";
              const running = task.status === "running";
              const taskStart = startedMs(task.started_at);
              const count = running
                ? typeof task.rows_so_far === "number"
                  ? `행 ${formatCount(task.rows_so_far)}`
                  : "—"
                : typeof task.artifact_count === "number"
                  ? `${formatCount(task.artifact_count)}건`
                  : "—";
              const duration =
                running && Number.isFinite(taskStart)
                  ? `${formatElapsed(now - taskStart)} 경과`
                  : durationText(task.duration_ms) || "—";
              const why =
                task.status === "partial" || task.status === "cancelled" || task.status === "skipped"
                  ? taskReasonText(task)
                  : "";
              const note = [task.message?.trim() ?? "", why, task.reused ? "이전 결과 재사용" : ""]
                .filter(Boolean)
                .join(" · ");
              const tooltip =
                why && task.requested_by?.at
                  ? `${why} (${formatTimestamp(task.requested_by.at, timezone)})`
                  : why || undefined;
              return (
                <tr
                  key={key}
                  {...common}
                  aria-level={2}
                  className="run-plan-task"
                  data-status={task.status}
                  data-testid={`run-plan-task-${task.id}`}
                >
                  <td className="run-plan-task-label">{task.label}</td>
                  <td>
                    <StatusBadge status={String(task.status)} title={tooltip} />
                  </td>
                  <td />
                  <td className="is-right">{count}</td>
                  <td className="is-right">{duration}</td>
                  <td className="process-plan-note" title={tooltip}>
                    {note || "—"}
                  </td>
                  <td>
                    <DisabledReason reason={reason}>
                      <button
                        type="button"
                        className="icon-btn run-plan-x"
                        aria-label={`${task.label} ${verb}`}
                        tabIndex={-1}
                        data-action-for={key}
                        data-action={action ?? "none"}
                        onClick={() => {
                          if (!action) return;
                          void send(action, [{ task: task.id }], `${task.label} ${verb}`);
                        }}
                      >
                        <Icon name="close" />
                      </button>
                    </DisabledReason>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
