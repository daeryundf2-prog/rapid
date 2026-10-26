/**
 * Analysis results in the 탐색 stage (plan analysis-workbench-p1 §4, console-ia §3): header
 * (label, description, last state, a link to the 처리 card that runs it), run history
 * (select a job to load its rows) and the result rows in the one DataGrid
 * (`collection: analysis`). Running / cancelling lives on the 처리 stage cards.
 */

import { useMemo } from "react";
import type { AnalysisState } from "../../api/analyses";
import { isAnalysisActive } from "../../api/analyses";
import { CommandButton } from "../../commands/CommandButton";
import { chipToneOf, ToneChip } from "../../components/ToneChip";
import type { CollectionRef } from "../../contracts/collection";
import { Icon } from "../../icons";
import { serializeRoute } from "../../router";
import { useRoute, useTimezone } from "../../state/hooks";
import { useAppStore } from "../../state/store";
import { formatTimestamp } from "../../utils/time";
import { DataGrid } from "../grid/DataGrid";
import { formatCount } from "../grid/gridUtils";
import {
  ANALYSIS_NODES,
  type AnalysisNodeDef,
  analysisNode,
  formatDuration,
  isAllFailed,
  kindLabel,
  latestForNode,
  nodeStateIcon,
  nodeStateLabel,
  ocrOutcome,
  progressText,
  STATUS_LABEL,
  selectedForNode,
  summaryNotes,
} from "./kinds";
import { useAnalyses } from "./store";
import "./analysis.css";

export function lastStateText(
  job: AnalysisState | undefined,
  timezone: string,
  { withError = true, prefix = "마지막 실행" }: { withError?: boolean; prefix?: string } = {},
): string {
  if (!job) return "아직 실행하지 않았습니다";
  const when = job.finished_at ?? job.started_at ?? job.created_at;
  // "완료 · 20건" for a batch whose 20 items all failed read as success: say it failed.
  const parts = [`${prefix}: ${isAllFailed(job) ? "전부 실패" : STATUS_LABEL[job.status]}`];
  if (when) parts.push(formatTimestamp(when, timezone));
  if (job.status === "completed" || job.status === "cancelled") parts.push(`${formatCount(job.row_count)}건`);
  if (isAnalysisActive(job)) {
    const progress = progressText(job);
    if (progress) parts.push(progress);
  }
  parts.push(...summaryNotes(job).filter((note) => withError || !note.startsWith("실패 사유:")));
  return parts.join(" · ");
}

/** Status cell text of a job: "전부 실패" for an all-failed batch, else the status label. */
export function jobStatusLabel(job: AnalysisState): string {
  return isAllFailed(job) ? "전부 실패" : STATUS_LABEL[job.status];
}

/** "실패 20" (OCR batches with failures) for the history status cell. */
function outcome(job: AnalysisState): string {
  const result = ocrOutcome(job);
  return result && result.failed > 0 && !isAnalysisActive(job)
    ? `성공 ${formatCount(result.succeeded)} · 실패 ${formatCount(result.failed)}`
    : "";
}

export function History({
  jobs,
  selectedId,
  onSelect,
}: {
  jobs: AnalysisState[];
  selectedId: string | undefined;
  onSelect: (job: AnalysisState) => void;
}) {
  const { timezone } = useTimezone();
  if (jobs.length === 0) return null;
  return (
    <div className="analysis-history-wrap">
      <table className="analysis-history" aria-label="실행 이력">
        <thead>
          <tr>
            <th scope="col">결과</th>
            <th scope="col">종류</th>
            <th scope="col">상태</th>
            <th scope="col">시작</th>
            <th scope="col">소요</th>
            <th scope="col">건수</th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((job) => {
            const selected = job.analysis_id === selectedId;
            const started = job.started_at ?? job.created_at;
            return (
              <tr key={job.analysis_id} className={selected ? "is-selected" : undefined}>
                <td>
                  <button
                    type="button"
                    className="grid-btn"
                    aria-pressed={selected}
                    aria-label={`${kindLabel(job.kind)} ${started ? formatTimestamp(started, timezone) : ""} 결과 보기`}
                    data-analysis-id={job.analysis_id}
                    onClick={() => onSelect(job)}
                  >
                    {selected ? "보는 중" : "보기"}
                  </button>
                </td>
                <td>{kindLabel(job.kind)}</td>
                <td>
                  <ToneChip tone={chipToneOf(isAllFailed(job) ? "failed" : job.status)}>
                    {jobStatusLabel(job)}
                  </ToneChip>
                  {outcome(job) ? <span className="analysis-error-text"> · {outcome(job)}</span> : null}
                  {job.error ? <span className="analysis-error-text"> · {job.error}</span> : null}
                </td>
                <td>{started ? formatTimestamp(started, timezone) : "—"}</td>
                <td>{isAnalysisActive(job) ? progressText(job) || "—" : formatDuration(job.elapsed_s)}</td>
                <td className="is-right">{formatCount(job.row_count)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** "선택한 스냅샷 비교…/추출…": the focused discover row prefills the compare / extract dialog. */
function SnapshotActions({ job }: { job: AnalysisState }) {
  if (job.kind !== "vsc-discover" || job.status !== "completed") return null;
  return (
    <>
      <CommandButton command="analysis.snapshot.compare" showReason />
      <CommandButton command="analysis.snapshot.extract" showReason />
    </>
  );
}

function Overview({ runId }: { runId: string }) {
  const { analyses } = useAnalyses(runId);
  return (
    <section className="analysis-pane" aria-labelledby="analysis-overview-title">
      <div className="analysis-head">
        <h2 id="analysis-overview-title">분석 결과</h2>
        <p className="analysis-desc">
          처리 단계에서 실행한 추가 분석의 결과입니다. 탐색 트리의 도메인 노드로도 열 수 있습니다.
        </p>
      </div>
      <ul className="analysis-overview">
        {ANALYSIS_NODES.map((node) => {
          const last = latestForNode(analyses, node);
          return (
            <li key={node.id}>
              <a
                className="stage-link"
                href={serializeRoute({ runId, collection: "analysis", kind: node.id })}
              >
                <Icon name={nodeStateIcon(last?.status ?? null)} />
                {node.label}
              </a>
              <span className="analysis-desc">
                {nodeStateLabel(last?.status ?? null)} · {node.description}
              </span>
              {/* Every result names where it is run (r7 L4, C-A2): the 처리 stage card of the node. */}
              <a
                className="stage-link analysis-run-link"
                href={serializeRoute({ runId, collection: "process", kind: node.id })}
                data-testid={`analysis-run-link-${node.id}`}
                aria-label={`${node.label}: 처리 단계에서 실행`}
              >
                처리 단계에서 실행 →
              </a>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function NodePane({ runId, node, routedId }: { runId: string; node: AnalysisNodeDef; routedId?: string }) {
  const { analyses, unavailable, error } = useAnalyses(runId);
  const { timezone } = useTimezone();
  const patchRoute = useAppStore((s) => s.patchRoute);
  const jobs = useMemo(
    () => analyses.filter((a) => (node.kinds as string[]).includes(a.kind)),
    [analyses, node],
  );
  const selected = selectedForNode(analyses, node, routedId);
  const last = jobs[0];
  const viewingOlder = Boolean(selected && last && selected.analysis_id !== last.analysis_id);
  const selectedId = selected?.analysis_id;
  const selectedKind = selected?.kind;
  const collection = useMemo<CollectionRef | null>(
    () =>
      selectedId && selectedKind ? { id: "analysis", kind: selectedKind, analysisId: selectedId } : null,
    [selectedId, selectedKind],
  );
  const titleId = `analysis-title-${node.id}`;

  return (
    <section className="analysis-pane" aria-labelledby={titleId} data-testid="analysis-pane">
      <div className="analysis-head">
        <h2 id={titleId}>{node.label}</h2>
        <p className="analysis-desc">{node.description}</p>
        {/* The header describes the job whose rows are shown: an older selected job (a capped
            compare, say) gets its own summary / truncated reason, and the newest one a short line. */}
        <p className="analysis-last" data-testid="analysis-last">
          <Icon name={nodeStateIcon((viewingOlder ? selected : last)?.status ?? null)} />
          {unavailable
            ? "이 서버는 분석 작업을 지원하지 않습니다"
            : viewingOlder
              ? lastStateText(selected, timezone, { prefix: "보고 있는 실행", withError: false })
              : lastStateText(last, timezone, {
                  // The selected failed job's reason has its own line below the history.
                  withError: last?.analysis_id !== selected?.analysis_id,
                })}
        </p>
        {!unavailable && viewingOlder && last ? (
          <p className="analysis-desc" data-testid="analysis-latest">
            {lastStateText(last, timezone, { prefix: "최신 실행" })}
          </p>
        ) : null}
        {error ? <p className="case-error">분석 목록을 불러오지 못했습니다: {error.message}</p> : null}
        <div className="analysis-actions">
          <a
            className="stage-link"
            href={serializeRoute({ runId, collection: "process", kind: node.id })}
            data-testid="analysis-process-link"
          >
            처리 단계에서 실행·취소 →
          </a>
          {selected ? <SnapshotActions job={selected} /> : null}
        </div>
      </div>
      <History
        jobs={jobs}
        selectedId={selectedId}
        onSelect={(job) =>
          patchRoute({ analysisId: job.analysis_id, row: undefined, mode: undefined, sort: undefined })
        }
      />
      {selected && selected.status === "failed" && selected.error ? (
        <p className="case-error analysis-failed">실패 사유: {selected.error}</p>
      ) : null}
      {collection ? (
        <div className="analysis-grid">
          <DataGrid collection={collection} />
        </div>
      ) : (
        <p className="pane-empty" data-testid="analysis-empty">
          {unavailable
            ? "이 서버는 분석 작업을 지원하지 않습니다."
            : "아직 실행하지 않았습니다 · 처리 단계의 추가 분석 카드에서 시작하세요."}
        </p>
      )}
    </section>
  );
}

/** Grid slot content for `#/case/{run}/explore/analysis[/{node}]`. */
export function AnalysisPane() {
  const { route } = useRoute();
  const runId = route.runId;
  if (!runId) return <p className="pane-empty">케이스를 먼저 선택하세요.</p>;
  if (!route.kind) return <Overview runId={runId} />;
  const node = analysisNode(route.kind);
  if (!node) return <p className="pane-empty">알 수 없는 분석 작업입니다: {route.kind}</p>;
  return <NodePane runId={runId} node={node} routedId={route.analysisId} />;
}
