/**
 * 처리 stage (console-ia §3): left panel = runs (status · elapsed · errors) + "추가 분석";
 * centre = the routed run's summary, the processing plan placeholder (existing step list;
 * the group/task table is P2) and one card per analysis (options dialog · run · progress ·
 * history · cancel · "결과 보기 →").
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { announce } from "../../a11y";
import { type AnalysisState, isAnalysisActive } from "../../api/analyses";
import { getRunSummary } from "../../api/runs";
import { RUN_MODE_LABEL, runDisplayName } from "../../app/collections";
import { CommandButton } from "../../commands/CommandButton";
import { StatusBadge, statusLabel } from "../../components/Badge";
import { Icon } from "../../icons";
import { serializeRoute } from "../../router";
import { formatElapsed, progressText as runProgressText } from "../../shell/StatusBar";
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
import { formatCount } from "../grid/gridUtils";
import "../analysis/analysis.css";
import "./stages.css";

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

/** Current time, ticking every second while `active` (run elapsed clocks). */
export function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [active]);
  return now;
}

/** Runs listed before "더 보기" in the 처리 panel (the routed run is always listed). */
export const RECENT_RUN_COUNT = 8;

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

/** Korean labels of run summary step statuses (processing plan table). */
const STEP_STATUS_LABEL: Record<string, string> = {
  completed: "완료",
  complete: "완료",
  ok: "완료",
  executed: "실행됨",
  skipped: "건너뜀",
  failed: "실패",
  error: "오류",
  running: "실행 중",
  queued: "대기",
  pending: "대기",
  cancelled: "취소됨",
  canceled: "취소됨",
  partial: "일부 완료",
  missing: "없음",
  blocked: "차단됨",
  unavailable: "사용할 수 없음",
  timeout: "시간 초과",
  not_run: "미실행",
  warning: "경고",
  warn: "경고",
  notice: "알림",
  info: "정보",
  none: "이상 없음",
  failed_isolated: "일부 실패(격리됨)",
  unknown: "알 수 없음",
  "operator-exercise": "분석관 확인 필요",
};

/** Korean status of a plan step; an unknown one still reads as Korean ("상태 미상(xyz)"). */
export function stepStatusLabel(status: string): string {
  const known = STEP_STATUS_LABEL[status] ?? STEP_STATUS_LABEL[status.toLowerCase()];
  if (known) return known;
  const lower = status.toLowerCase();
  if (lower.includes("warn")) return "경고";
  if (lower.includes("fail") || lower.includes("error")) return "실패";
  return `상태 미상(${status})`;
}

/** Korean names of the run pipeline steps (core/run/steps.py `name`). */
const STEP_NAME_LABEL: Record<string, string> = {
  manifest: "증거 목록(매니페스트)",
  docs: "문서 텍스트 추출",
  "docs-index": "문서 색인",
  files: "파일 목록",
  "docs-extract": "문서 추출",
  "files-extract": "파일 추출",
  timeline: "타임라인",
  indicators: "지표(IOC) 요약",
  "silent-failure-detector": "누락 위험 점검",
  triage: "분류",
  prepare: "준비",
  finalize: "마무리",
};

/** Korean name of a plan step (`artifacts-<kind>` → "아티팩트 수집: <kind>"); unknown ids stay as-is. */
export function stepNameLabel(name: string): string {
  const known = STEP_NAME_LABEL[name] ?? STEP_NAME_LABEL[name.toLowerCase()];
  if (known) return known;
  if (name.startsWith("artifacts-")) return `아티팩트 수집: ${name.slice("artifacts-".length)}`;
  return name;
}

/** Korean warning level of a plan step (`warning_level`); "" for none. */
export function stepWarningLabel(level: string): string {
  if (!level || level === "none") return "";
  return stepStatusLabel(level);
}

/** Left panel of the 처리 stage: 추가 분석 first, then the runs (recent N, "더 보기"). */
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
      <ul aria-labelledby="process-analyses-title">
        {runId
          ? ANALYSIS_NODES.map((node) => {
              const last = latestForNode(analyses, node);
              const current = route.collection === "process" && route.kind === node.id;
              const state = nodeStateLabel(last?.status ?? null);
              return (
                <li key={node.id}>
                  <a
                    className="stage-link"
                    href={serializeRoute({ runId, collection: "process", kind: node.id })}
                    aria-current={current ? "page" : undefined}
                    aria-label={`${node.label}, ${state}`}
                  >
                    <Icon name={nodeStateIcon(last?.status ?? null)} size={14} />
                    <span>{node.label}</span>
                    <span className="badge muted">{state}</span>
                  </a>
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

/** Existing step list of the run summary (the P2 group/task table takes this place). */
function StepList({ runId }: { runId: string }) {
  const summary = useQuery({
    queryKey: ["run-summary", runId],
    queryFn: () => getRunSummary(runId),
    retry: false,
  });
  const steps = summary.data?.steps ?? [];
  const text = (v: unknown) => (typeof v === "string" || typeof v === "number" ? String(v) : "");
  return (
    <section className="stage-section" aria-labelledby="process-plan-title">
      <h3 id="process-plan-title">처리 계획</h3>
      <p className="analysis-desc">
        그룹·태스크 단위 계획표(취소·재실행)는 다음 단계(P2)에서 이 자리에 들어옵니다.
      </p>
      {steps.length === 0 ? (
        <p className="analysis-desc">
          {summary.isPending ? "단계 목록을 불러오는 중…" : "기록된 처리 단계가 없습니다."}
        </p>
      ) : (
        <div className="analysis-history-wrap">
          <table className="analysis-history" aria-label="처리 단계">
            <thead>
              <tr>
                <th scope="col">단계</th>
                <th scope="col">상태</th>
                <th scope="col">건수</th>
                <th scope="col">소요</th>
              </tr>
            </thead>
            <tbody>
              {steps.map((step, index) => {
                const id = text(step.step ?? step.name ?? step.kind);
                const status = text(step.status) ? stepStatusLabel(text(step.status)) : "";
                const warning = stepWarningLabel(text(step.warning_level));
                return (
                  // biome-ignore lint/suspicious/noArrayIndexKey: steps have no id; order is stable
                  <tr key={index}>
                    <td title={id || undefined}>{id ? stepNameLabel(id) : `단계 ${index + 1}`}</td>
                    <td>
                      {status || "—"}
                      {warning && warning !== status ? ` · ${warning}` : ""}
                    </td>
                    <td className="is-right">
                      {text(step.record_count ?? step.count ?? step.output_count) || "—"}
                    </td>
                    <td>{text(step.elapsed_s ?? step.duration_s ?? step.elapsed) || "—"}</td>
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
        <Icon name={nodeStateIcon(last ? (isAllFailed(last) ? "failed" : last.status) : null)} size={14} />
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
  if (!runId) return <p className="pane-empty">케이스를 먼저 선택하세요.</p>;
  const run = currentRun;
  return (
    <section className="stage-page" aria-labelledby="process-title" data-testid="process-page">
      <h2 id="process-title">처리</h2>
      <section className="stage-section" aria-labelledby="process-run-title">
        <h3 id="process-run-title">런 {run ? runDisplayName(run) : runId.slice(0, 8)}</h3>
        {run ? (
          <dl className="stage-dl">
            <dt>상태</dt>
            <dd>
              <StatusBadge status={String(run.status)} />
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
        <div className="analysis-actions">
          <CommandButton command="case.cancel" label="런 취소" />
          <CommandButton command="case.retry" label="런 다시 실행" />
        </div>
      </section>
      <StepList runId={runId} />
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
