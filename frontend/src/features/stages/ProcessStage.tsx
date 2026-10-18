/**
 * 처리 stage (console-ia §3): left panel = runs (status · elapsed · errors) + "추가 분석";
 * centre = the routed run's summary, the processing plan placeholder (existing step list;
 * the group/task table is P2) and one card per analysis (options dialog · run · progress ·
 * history · cancel · "결과 보기 →").
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { announce, DisabledReason } from "../../a11y";
import { type AnalysisState, isAnalysisActive } from "../../api/analyses";
import { ApiError } from "../../api/client";
import { useRunPlan } from "../../api/runPlan";
import { getRunSummary, normalizeRunStatus, RETRYABLE_RUN_STATUSES } from "../../api/runs";
import { RUN_MODE_LABEL, runDisplayName } from "../../app/collections";
import { CommandButton } from "../../commands/CommandButton";
import { useCommandState } from "../../commands/registry";
import { StatusBadge, statusLabel } from "../../components/Badge";
import { chipToneOf, ToneChip } from "../../components/ToneChip";
import { Icon } from "../../icons";
import { serializeRoute } from "../../router";
import { formatElapsed, progressText as runProgressText, staleText } from "../../shell/StatusBar";
import { useRoute, useRuns, useTimezone } from "../../state/hooks";
import { isRunActive } from "../../state/slices/runs";
import { useAppStore } from "../../state/store";
import { formatTimestamp } from "../../utils/time";
import { History, lastStateText } from "../analysis/AnalysisPane";
import { cancelAnalysisJob, runCommandId } from "../analysis/commands";
import {
  ANALYSIS_NODES,
  type AnalysisNodeDef,
  isAllFailed,
  isPartialResult,
  kindLabel,
  latestForNode,
  nodeStateIcon,
  nodeStateLabel,
  progressText,
  STATUS_LABEL,
} from "../analysis/kinds";
import { useAnalyses } from "../analysis/store";
import { DisclosuresCard } from "../dashboard/cards";
import { disclosureDigest, disclosureItems, runWarnings } from "../dashboard/disclosures";
import { formatCount } from "../grid/gridUtils";
import { RunPlanTable } from "./RunPlanTable";
import { stepNameLabel, stepStatusLabel, stepWarningLabel } from "./stepLabels";
import { useNow } from "./useNow";
import "../analysis/analysis.css";
import "../dashboard/dashboard.css";
import "./stages.css";

export { stepNameLabel, stepStatusLabel, stepWarningLabel } from "./stepLabels";

function elapsedOf(
  run: { created_at?: string; updated_at?: string; finished_at?: string | null; status?: unknown },
  now: number,
): string {
  const start = run.created_at ? Date.parse(run.created_at) : Number.NaN;
  if (!Number.isFinite(start)) return "—";
  const finished = run.finished_at ?? run.updated_at;
  const end = isRunActive(run) ? now : finished ? Date.parse(finished) : Number.NaN;
  return Number.isFinite(end) ? formatElapsed(end - start) : "—";
}

export { useNow };

/** Runs listed before "더 보기" in the 처리 panel (the routed run is always listed). */
export const RECENT_RUN_COUNT = 5;

type RunLike = { run_id: string; created_at?: string; request?: { root?: string; output_dir?: string } };

/** One run's list label: the shared name, and what tells it apart (start time · short id). */
export interface RunNameParts {
  name: string;
  /** "2026-10-12 11:26 · 2a942078" for a name shared by several runs, else "". */
  detail: string;
  /** Tooltip: full name, start time and the full run id. */
  tooltip: string;
}

export function runNameParts(runs: readonly RunLike[], timezone: string): Map<string, RunNameParts> {
  const counts = new Map<string, number>();
  for (const run of runs) {
    const name = runDisplayName(run);
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  const out = new Map<string, RunNameParts>();
  for (const run of runs) {
    const name = runDisplayName(run);
    const when = run.created_at ? formatTimestamp(run.created_at, timezone, { precision: "minute" }) : "";
    const detail =
      (counts.get(name) ?? 0) < 2 ? "" : [when, run.run_id.slice(0, 8)].filter(Boolean).join(" · ");
    const tooltip = [name, when, run.run_id].filter(Boolean).join(" · ");
    out.set(run.run_id, { name, detail, tooltip });
  }
  return out;
}

/**
 * Display names for a run list: a name shared by several runs ("evidence", "BSH.E01") gets
 * the start time and the short run id appended, so the list never shows identical rows.
 */
export function disambiguatedRunNames(runs: readonly RunLike[], timezone: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const [id, parts] of runNameParts(runs, timezone)) {
    out.set(id, parts.detail ? `${parts.name} · ${parts.detail}` : parts.name);
  }
  return out;
}

/** "완료 · 10-12 21:37 · 35건" — the compact last-run line of a 처리 panel card. */
export function lastRunShort(job: AnalysisState | undefined, timezone: string): string {
  if (!job) return "아직 실행하지 않았습니다";
  const when = job.finished_at ?? job.started_at ?? job.created_at;
  const parts = [isAllFailed(job) ? "전부 실패" : STATUS_LABEL[job.status]];
  if (when) parts.push(formatTimestamp(when, timezone, { precision: "minute" }));
  if (job.status === "completed" || job.status === "cancelled") parts.push(`${formatCount(job.row_count)}건`);
  if (isAnalysisActive(job)) {
    const progress = progressText(job);
    if (progress) parts.push(progress);
  }
  return parts.join(" · ");
}

/** Run button of a panel card: the node's first analysis kind, opening its options dialog. */
function PanelRunButton({ kind, label }: { kind: string; label: string }) {
  const { command, disabledReason, run } = useCommandState(runCommandId(kind));
  if (!command) return null;
  return (
    <DisabledReason reason={disabledReason}>
      <button
        type="button"
        className="icon-btn process-card-run"
        aria-label={`${label} 실행`}
        title={disabledReason ? undefined : command.label}
        data-command={command.id}
        onClick={() => void run()}
      >
        <Icon name="play" />
      </button>
    </DisabledReason>
  );
}

/**
 * Left panel of the 처리 stage (visual-polish S8): one card per analysis — state, last run,
 * run button — first, then the recent runs (RECENT_RUN_COUNT, "더 보기").
 */
export function ProcessPanel() {
  const { route } = useRoute();
  const { runs } = useRuns();
  const { timezone } = useTimezone();
  const runId = route.runId;
  const { analyses } = useAnalyses(runId);
  const now = useNow(runs.some(isRunActive));
  const [showAll, setShowAll] = useState(false);
  const names = runNameParts(runs, timezone);
  const shown = showAll
    ? runs
    : runs.filter((run, index) => index < RECENT_RUN_COUNT || run.run_id === runId);
  const hidden = runs.length - shown.length;
  return (
    <div className="stage-panel" data-testid="process-panel">
      <h2 id="process-analyses-title">추가 분석</h2>
      <ul aria-labelledby="process-analyses-title" className="process-cards">
        {runId
          ? ANALYSIS_NODES.map((node) => {
              const nodeJobs = analyses.filter((job) => (node.kinds as string[]).includes(job.kind));
              const last = latestForNode(analyses, node);
              const current = route.collection === "process" && route.kind === node.id;
              const state = nodeStateLabel(last?.status ?? null);
              const failed = last ? isAllFailed(last) : false;
              return (
                <li
                  key={node.id}
                  className={`process-card${current ? " is-current" : ""}`}
                  data-testid={`process-analysis-${node.id}`}
                  data-state={failed ? "failed" : (last?.status ?? "none")}
                >
                  <a
                    className="process-card-link"
                    href={serializeRoute({ runId, collection: "process", kind: node.id })}
                    aria-current={current ? "page" : undefined}
                    aria-label={`${node.label}, ${state}`}
                  >
                    {/* State as a dot + text chip (review #11): no leading status glyph. */}
                    <span className="process-card-title">{node.label}</span>
                    <ToneChip tone={chipToneOf(failed ? "failed" : (last?.status ?? null))}>{state}</ToneChip>
                  </a>
                  <span className="process-card-last">
                    {lastRunShort(nodeJobs.find(isAnalysisActive) ?? last, timezone)}
                  </span>
                  <PanelRunButton kind={node.kinds[0] as string} label={node.label} />
                </li>
              );
            })
          : null}
      </ul>
      <h2 id="process-runs-title">런</h2>
      <ul id="process-run-list" aria-labelledby="process-runs-title" data-testid="process-run-list">
        {shown.map((run) => {
          const current = run.run_id === runId;
          const errors = run.progress?.error_count ?? 0;
          const parts = names.get(run.run_id) ?? {
            name: runDisplayName(run),
            detail: "",
            tooltip: `${runDisplayName(run)} · ${run.run_id}`,
          };
          const elapsed = elapsedOf(run, now);
          const label = [
            parts.detail ? `${parts.name} · ${parts.detail}` : parts.name,
            statusLabel(String(run.status)),
            `소요 ${elapsed}`,
            errors > 0 ? `오류 ${errors}` : "",
          ]
            .filter(Boolean)
            .join(", ");
          return (
            <li key={run.run_id}>
              <a
                className="stage-link"
                href={serializeRoute({ runId: run.run_id, collection: "process" })}
                aria-current={current ? "page" : undefined}
                aria-label={label}
                title={parts.tooltip}
              >
                {/* The distinguishing date · id gets its own line (the shared name ellipsizes). */}
                <span className="stage-link-name">
                  <span className="stage-link-title">{parts.name}</span>
                  {parts.detail ? (
                    <>
                      <span className="stage-link-sep"> · </span>
                      <span className="stage-link-detail">{parts.detail}</span>
                    </>
                  ) : null}
                </span>
                <StatusBadge status={String(run.status)} />
                <span className="badge muted">{elapsed}</span>
                {errors > 0 ? <span className="badge muted">오류 {errors}</span> : null}
              </a>
            </li>
          );
        })}
      </ul>
      {hidden > 0 || showAll ? (
        <button
          type="button"
          className="button ghost stage-more"
          aria-expanded={showAll}
          aria-controls="process-run-list"
          onClick={() => setShowAll((open) => !open)}
        >
          {showAll ? "최근 런만 보기" : `더 보기 (${formatCount(hidden)}개 더)`}
        </button>
      ) : null}
    </div>
  );
}

/** Count fields of a summary step, in the order the 건수 column prefers them, with their noun. */
const STEP_COUNT_KEYS: ReadonlyArray<[string, string]> = [
  ["record_count", "행"],
  ["artifact_count", "아티팩트"],
  ["candidate_count", "후보"],
  ["document_count", "문서"],
  ["event_count", "이벤트"],
  ["indicator_count", "지표"],
  ["match_count", "일치"],
  ["provider_count", "수집기"],
  ["extracted_count", "추출"],
  ["check_count", "점검"],
  ["count", "건"],
  ["output_count", "건"],
];

/** "후보 4,770" — the main count of a step, or "" when the step reports none. */
export function stepCountText(step: Record<string, unknown>): string {
  for (const [key, noun] of STEP_COUNT_KEYS) {
    const value = step[key];
    // Older summaries write counts as strings ("4770"): read those too.
    const count =
      typeof value === "number"
        ? value
        : typeof value === "string" && /^\d+$/.test(value.trim())
          ? Number(value)
          : Number.NaN;
    if (Number.isFinite(count)) return `${noun} ${formatCount(count)}`;
  }
  return "";
}

/** 비고 of a step: off by default, parser errors, risk checks, reuse, notices. */
export function stepNoteText(step: Record<string, unknown>): string {
  const notes: string[] = [];
  if (step.disabled === true) {
    const reason = typeof step.disabled_reason === "string" ? step.disabled_reason : "";
    notes.push(reason.includes("disabled-by-default") ? "기본 설정에서 꺼짐" : "꺼짐");
  }
  if (typeof step.parser_error_count === "number" && step.parser_error_count > 0)
    notes.push(`파서 오류 ${formatCount(step.parser_error_count)}`);
  if (typeof step.risk_check_count === "number" && step.risk_check_count > 0)
    notes.push(`위험 점검 ${formatCount(step.risk_check_count)}건`);
  if (typeof step.scanned_file_count === "number") notes.push(`스캔 ${formatCount(step.scanned_file_count)}`);
  if (step.reused === true) notes.push("이전 결과 재사용");
  const messages = Array.isArray(step.warning_messages) ? step.warning_messages.length : 0;
  if (messages > 0) notes.push(`메시지 ${messages}건`);
  return notes.join(" · ");
}

/**
 * 처리 계획 (visual-polish S8): the run summary's steps as a full table in Korean — 단계 · 상태 ·
 * 건수 · 비고 — with a status tally above it: the fallback of a run without a plan (written before
 * R4 V1). With a plan (`planned`) only the 공개 사항 digest is left here.
 */
function StepList({ runId, planned = false }: { runId: string; planned?: boolean }) {
  const summary = useQuery({
    queryKey: ["run-summary", runId],
    queryFn: () => getRunSummary(runId),
    retry: false,
  });
  const steps = (summary.data?.steps ?? []) as Array<Record<string, unknown>>;
  const disclosures = disclosureItems(summary.data);
  const warnings = runWarnings(summary.data);
  if (planned) {
    return disclosures.length || warnings.length ? (
      <details className="process-plan-disclosures" data-testid="process-disclosures">
        <summary>{disclosureDigest(summary.data)}</summary>
        <DisclosuresCard items={disclosures} warnings={warnings} />
      </details>
    ) : null;
  }
  const text = (v: unknown) => (typeof v === "string" || typeof v === "number" ? String(v) : "");
  const timed = steps.some((step) => text(step.elapsed_s ?? step.duration_s ?? step.elapsed) !== "");
  const tally = new Map<string, number>();
  for (const step of steps) {
    const label = text(step.status) ? stepStatusLabel(text(step.status)) : "상태 없음";
    tally.set(label, (tally.get(label) ?? 0) + 1);
  }
  return (
    <section className="stage-section process-plan" aria-labelledby="process-plan-title">
      <div className="process-plan-head">
        <h3 id="process-plan-title">처리 계획</h3>
        {steps.length ? (
          <p className="process-plan-tally">
            {[`${steps.length}단계`, ...[...tally].map(([label, n]) => `${label} ${n}`)].join(" · ")}
          </p>
        ) : null}
      </div>
      {disclosures.length || warnings.length ? (
        <details className="process-plan-disclosures" data-testid="process-disclosures">
          <summary>{disclosureDigest(summary.data)}</summary>
          <DisclosuresCard items={disclosures} warnings={warnings} />
        </details>
      ) : null}
      {steps.length === 0 ? (
        <p className="analysis-desc">
          {summary.isPending ? "단계 목록을 불러오는 중…" : "기록된 처리 단계가 없습니다."}
        </p>
      ) : (
        <div className="process-plan-wrap">
          <table className="analysis-history process-plan-table" aria-label="처리 단계">
            <thead>
              <tr>
                <th scope="col">단계</th>
                <th scope="col">상태</th>
                <th scope="col" className="is-right">
                  건수
                </th>
                <th scope="col">비고</th>
                {timed ? <th scope="col">소요</th> : null}
              </tr>
            </thead>
            <tbody>
              {steps.map((step, index) => {
                const id = text(step.step ?? step.name ?? step.kind);
                const status = text(step.status) ? stepStatusLabel(text(step.status)) : "";
                const warning = stepWarningLabel(text(step.warning_level));
                const messages = Array.isArray(step.warning_messages)
                  ? step.warning_messages.filter((m): m is string => typeof m === "string")
                  : [];
                return (
                  // biome-ignore lint/suspicious/noArrayIndexKey: steps have no id; order is stable
                  <tr key={index} data-status={text(step.status) || undefined}>
                    <td title={id || undefined}>{id ? stepNameLabel(id) : `단계 ${index + 1}`}</td>
                    <td>
                      {/* Step state as the shared dot + text chip (review #24). */}
                      {status ? (
                        <ToneChip
                          tone={warning && warning !== status ? "warn" : chipToneOf(text(step.status))}
                        >
                          {`${status}${warning && warning !== status ? ` · ${warning}` : ""}`}
                        </ToneChip>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="is-right">{stepCountText(step) || "—"}</td>
                    <td className="process-plan-note" title={messages.join("\n") || undefined}>
                      {stepNoteText(step) || "—"}
                    </td>
                    {timed ? <td>{text(step.elapsed_s ?? step.duration_s ?? step.elapsed) || "—"}</td> : null}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function AnalysisCard({
  runId,
  node,
  jobs,
  selected,
}: {
  runId: string;
  node: AnalysisNodeDef;
  jobs: AnalysisState[];
  selected: boolean;
}) {
  const { timezone } = useTimezone();
  const ref = useRef<HTMLElement>(null);
  const [picked, setPicked] = useState<string | undefined>(undefined);
  const [cancelling, setCancelling] = useState(false);
  const queryClient = useQueryClient();
  const last = jobs[0];
  const chosen = jobs.find((job) => job.analysis_id === picked);
  // One 결과 link per API kind (볼륨 섀도우: 탐색 / 비교 / 추출, each with its own count): the
  // history row the analyst selected for its kind, else that kind's newest completed job, else
  // its newest cancelled / failed job that still wrote rows (a partial result).
  const multiKind = node.kinds.length > 1;
  const resultLinks = node.kinds
    .map((kind) =>
      chosen && chosen.kind === kind
        ? chosen
        : (jobs.find((job) => job.kind === kind && job.status === "completed") ??
          jobs.find((job) => job.kind === kind && isPartialResult(job))),
    )
    .filter((job): job is AnalysisState => Boolean(job));
  const active = jobs.find(isAnalysisActive);
  useEffect(() => {
    if (selected) ref.current?.scrollIntoView?.({ block: "nearest" });
  }, [selected]);
  const titleId = `analysis-card-${node.id}`;
  return (
    <section
      ref={ref}
      className={`analysis-card${selected ? " is-selected" : ""}`}
      aria-labelledby={titleId}
      data-testid={`analysis-card-${node.id}`}
    >
      <h3 id={titleId}>
        <Icon name={nodeStateIcon(last ? (isAllFailed(last) ? "failed" : last.status) : null)} />
        {node.label}
      </h3>
      <p className="analysis-desc">{node.description}</p>
      <p className="analysis-last" data-testid="analysis-last">
        {lastStateText(last, timezone)}
      </p>
      {active ? (
        <p className="analysis-desc">
          진행: {progressText(active) || "대기 중"}
          {typeof active.progress.percent === "number" ? (
            <progress
              className="status-progress"
              max={100}
              value={Math.max(0, Math.min(100, active.progress.percent))}
              aria-label={`${node.label} 진행률`}
            />
          ) : null}
        </p>
      ) : null}
      <div className="analysis-actions">
        {node.kinds.map((kind) => (
          <CommandButton
            key={kind}
            command={runCommandId(kind)}
            variant={jobs.length ? "default" : "primary"}
            showReason
          />
        ))}
        {active ? (
          // This card's own job — not `analysis.cancel`, whose target follows the route.
          <button
            type="button"
            className="button"
            data-testid="analysis-cancel"
            disabled={cancelling}
            onClick={() => {
              setCancelling(true);
              cancelAnalysisJob(queryClient, runId, active)
                .catch((error: unknown) => {
                  const message = `분석 취소 실패: ${error instanceof Error ? error.message : String(error)}`;
                  useAppStore.getState().showNotice(message, "error");
                  announce(message, { politeness: "assertive" });
                })
                .finally(() => setCancelling(false));
            }}
          >
            <Icon name="stop" />
            <span>분석 취소</span>
          </button>
        ) : null}
        {resultLinks.length === 0 ? <span className="analysis-desc">결과 없음</span> : null}
      </div>
      {resultLinks.length ? (
        <ul className="analysis-result-links" aria-label={`${node.label} 결과`}>
          {resultLinks.map((job) => (
            <li key={job.kind}>
              <a
                className="stage-link"
                data-testid="analysis-results-link"
                data-kind={job.kind}
                href={serializeRoute({
                  runId,
                  collection: "analysis",
                  kind: node.id,
                  analysisId: job.analysis_id,
                })}
              >
                {isPartialResult(job)
                  ? `${multiKind ? `${kindLabel(job.kind)} ` : ""}부분 결과 ${formatCount(job.row_count)}건 보기 → (${STATUS_LABEL[job.status]})`
                  : `${multiKind ? `${kindLabel(job.kind)} 결과` : "결과 보기"} → (${formatCount(job.row_count)}건)`}
              </a>
            </li>
          ))}
        </ul>
      ) : null}
      {selected ? (
        <History
          jobs={jobs}
          selectedId={chosen?.analysis_id}
          onSelect={(job) => setPicked((prev) => (prev === job.analysis_id ? undefined : job.analysis_id))}
        />
      ) : null}
    </section>
  );
}

/** Centre of the 처리 stage. */
export function ProcessPage() {
  const { route } = useRoute();
  const { currentRun } = useRuns();
  const { timezone } = useTimezone();
  const runId = route.runId;
  const { analyses, unavailable } = useAnalyses(runId);
  const now = useNow(isRunActive(currentRun));
  const plan = useRunPlan(runId ?? null, currentRun?.status);
  if (!runId) return <p className="pane-empty">케이스를 먼저 선택하세요.</p>;
  const run = currentRun;
  const runStatus = normalizeRunStatus(run?.status);
  const active = isRunActive(run);
  const retryable = RETRYABLE_RUN_STATUSES.has(runStatus);
  return (
    <section className="stage-page" aria-labelledby="process-title" data-testid="process-page">
      <h2 id="process-title">처리</h2>
      <section className="stage-section" aria-labelledby="process-run-title">
        <h3 id="process-run-title">런 {run ? runDisplayName(run) : runId.slice(0, 8)}</h3>
        {run ? (
          <dl className="stage-dl">
            <dt>상태</dt>
            <dd data-testid="process-run-status">
              <StatusBadge status={String(run.status)} />
              {runStatus === "interrupted" ? <span className="process-run-note"> · 서버 재시작</span> : null}
              {staleText(run, now) ? (
                <span className="process-run-note is-warn"> · {staleText(run, now)}</span>
              ) : null}
            </dd>
            <dt>모드</dt>
            <dd>{RUN_MODE_LABEL[String(run.request?.mode ?? "")] ?? run.request?.mode ?? "—"}</dd>
            <dt>증거 경로</dt>
            <dd className="mono">{run.request?.root ?? "—"}</dd>
            <dt>시작</dt>
            <dd>{run.created_at ? formatTimestamp(run.created_at, timezone) : "—"}</dd>
            <dt>소요</dt>
            <dd>{elapsedOf(run, now)}</dd>
            <dt>진행</dt>
            <dd>{runProgressText(run) || "—"}</dd>
            <dt>오류</dt>
            <dd>{run.progress?.error_count ?? 0}</dd>
          </dl>
        ) : (
          <p className="analysis-desc">런 정보를 불러오는 중…</p>
        )}
        {/* Run controls (R4 V1): 모두 취소 / 마치기 while it runs; 이어서 실행 (completed tasks
            reused) / 처음부터 다시 after a failure, a cancel or a server restart. */}
        {active || retryable ? (
          <div className="analysis-actions" data-testid="process-run-actions">
            {active ? (
              <>
                <CommandButton command="run.plan.cancelAll" label="모두 취소" testId="process-cancel-all" />
                <CommandButton command="run.plan.finish" label="마치기" testId="process-finish" />
              </>
            ) : (
              <>
                <CommandButton
                  command="run.resume"
                  label="이어서 실행"
                  variant="primary"
                  testId="process-resume"
                />
                <CommandButton command="case.retry" label="처음부터 다시" testId="process-restart" />
              </>
            )}
          </div>
        ) : null}
      </section>
      {plan.data ? <RunPlanTable key={runId} runId={runId} plan={plan.data} controls={false} /> : null}
      {!plan.data && plan.error && !(plan.error instanceof ApiError && plan.error.status === 404) ? (
        // A run written before R4 has no plan (404 → the step list alone); any other failure is said.
        <p className="run-plan-stale" role="status" data-testid="run-plan-error">
          처리 계획을 불러오지 못했습니다: {plan.error.message}
        </p>
      ) : null}
      <StepList runId={runId} planned={Boolean(plan.data)} />
      <section aria-labelledby="process-analyses-heading">
        <h3 id="process-analyses-heading">추가 분석</h3>
        {unavailable ? <p className="analysis-desc">이 서버는 분석 작업을 지원하지 않습니다.</p> : null}
        <div className="analysis-cards">
          {ANALYSIS_NODES.map((node) => (
            <AnalysisCard
              key={node.id}
              runId={runId}
              node={node}
              jobs={analyses.filter((job) => (node.kinds as string[]).includes(job.kind))}
              selected={route.kind === node.id}
            />
          ))}
        </div>
      </section>
    </section>
  );
}
