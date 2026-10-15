/**
 * Status-bar chip for the run's queued/running analysis jobs (plan analysis-workbench-p1 §4):
 * "카빙 42% · 소스 파일 12/30 · 메시지" + 취소 (the `analysis.cancel` command). It owns the
 * 1 s poll of `GET /analyses` — polling stops when no job is active and when it unmounts.
 * Transitions are announced through the single polite live region (no live region here).
 */

import { isAnalysisActive } from "../../api/analyses";
import { focusGridWhenReady } from "../../commands/builtin";
import { CommandButton } from "../../commands/CommandButton";
import { Icon } from "../../icons";
import { useRoute } from "../../state/hooks";
import { openAnalysis } from "./commands";
import { kindLabel, progressText } from "./kinds";
import { useAnalyses, useAnalysisTransitions } from "./store";
import "./analysis.css";

export function AnalysisProgressChip() {
  const { route } = useRoute();
  const runId = route.runId;
  const { analyses, loading } = useAnalyses(runId, { poll: true });
  useAnalysisTransitions(runId, analyses, { loaded: !loading });
  const active = analyses.filter(isAnalysisActive);
  if (!runId || active.length === 0) return null;
  const job = active[0];
  if (!job) return null;
  const percent = job.progress.percent;
  const text = progressText(job);
  const more = active.length > 1 ? ` 외 ${active.length - 1}건` : "";
  return (
    <span className="status-analysis" data-testid="analysis-progress-chip">
      <span className="status-analysis-text">
        <Icon name="spinner" className="spin" />
        분석: {kindLabel(job.kind)}
        {more}
        {text ? ` · ${text}` : ""}
      </span>
      {typeof percent === "number" ? (
        <progress
          className="status-progress"
          max={100}
          value={Math.max(0, Math.min(100, percent))}
          aria-label={`${kindLabel(job.kind)} 진행률`}
        />
      ) : null}
      {/* Opens the job this chip names (not analysis.openLast, which prefers the newest completed). */}
      <button
        type="button"
        className="button ghost"
        data-testid="analysis-chip-open"
        onClick={() => {
          openAnalysis(runId, job.kind, job.analysis_id);
          focusGridWhenReady();
        }}
      >
        <span>분석 보기</span>
      </button>
      <CommandButton
        command="analysis.cancel"
        label="분석 취소"
        variant="ghost"
        testId="analysis-chip-cancel"
      />
    </span>
  );
}
