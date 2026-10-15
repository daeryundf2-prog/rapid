/**
 * Analysis commands (plan analysis-workbench-p1 §4): `analysis.run.<kind>` opens the run
 * dialog ("카빙 실행…" is findable in the palette), `analysis.cancel` cancels the running
 * job, `analysis.openLast` opens the newest job's results. No shortcuts (KEY_MAP is full).
 */

import type { QueryClient } from "@tanstack/react-query";
import { announce } from "../../a11y";
import {
  ANALYSIS_KINDS,
  type AnalysisKind,
  type AnalysisState,
  cancelAnalysis,
  isAnalysisActive,
} from "../../api/analyses";
import { focusGridWhenReady } from "../../commands/builtin";
import { NO_RUN_REASON } from "../../commands/reasons";
import { registerCommands } from "../../commands/registry";
import type { Command, CommandContext } from "../../contracts/command";
import { currentRun } from "../../state/slices/runs";
import { useAppStore } from "../../state/store";
import { useGridLocalStore } from "../grid/adapter";
import { isRecord } from "../grid/columns/common";
import { kindLabel, nodeOfKind } from "./kinds";
import { ANALYSES_UNAVAILABLE_REASON, analysesFor, analysesQueryKey, useAnalysisStore } from "./store";

export const RUN_NOT_FINISHED_REASON = "런이 끝난(완료·실패) 뒤에만 분석을 실행할 수 있습니다";
export const ALREADY_RUNNING_REASON = "이미 실행 중인 분석이 있습니다";
export const NEEDS_DISCOVER_REASON = "먼저 볼륨 섀도우 탐색을 완료하세요";
export const NOTHING_RUNNING_REASON = "실행 중인 분석이 없습니다";
export const NO_ANALYSIS_REASON = "아직 실행한 분석이 없습니다";
export const NO_SNAPSHOT_ROW_REASON = "볼륨 섀도우 탐색 결과에서 스냅샷 행을 먼저 선택하세요";

/** snapshot_root of the focused volume-shadow discovery result row, if any. */
export function focusedSnapshotRoot(): string {
  const row = useGridLocalStore.getState().focusedRow;
  if (row?.ref.collection !== "analysis" || row.fields.kind !== "vsc-discover") return "";
  const details = isRecord(row.fields.details) ? row.fields.details : {};
  return typeof details.snapshot_root === "string" ? details.snapshot_root : "";
}

export function runCommandId(kind: AnalysisKind | string): string {
  return `analysis.run.${kind}`;
}

/** Why a job of `kind` cannot start now (undefined = it can). */
export function runDisabledReason(
  kind: AnalysisKind,
  ctx: Pick<CommandContext, "runId">,
): string | undefined {
  if (!ctx.runId) return NO_RUN_REASON;
  const store = useAnalysisStore.getState();
  if (store.runId === ctx.runId && !store.available) return ANALYSES_UNAVAILABLE_REASON;
  const run = currentRun(useAppStore.getState());
  const status = run ? String(run.status ?? "") : "";
  if (run && status !== "completed" && status !== "failed") return RUN_NOT_FINISHED_REASON;
  const jobs = analysesFor(ctx.runId);
  if (jobs.some((job) => job.kind === kind && isAnalysisActive(job))) return ALREADY_RUNNING_REASON;
  if (
    (kind === "vsc-compare" || kind === "vsc-extract") &&
    !jobs.some((job) => job.kind === "vsc-discover" && job.status === "completed")
  ) {
    return NEEDS_DISCOVER_REASON;
  }
  return undefined;
}

/** The job `analysis.cancel` acts on: the routed node's running job, else the newest running one. */
export function cancelTarget(runId: string | null) {
  const jobs = analysesFor(runId).filter(isAnalysisActive);
  if (jobs.length === 0) return undefined;
  const route = useAppStore.getState().route;
  if ((route.collection === "analysis" || route.collection === "process") && route.kind) {
    const routed = jobs.find((job) => job.analysis_id === route.analysisId);
    if (routed) return routed;
    const sameNode = jobs.find((job) => nodeOfKind(job.kind)?.id === route.kind);
    if (sameNode) return sameNode;
  }
  return jobs[0];
}

/** Cancel one specific job (the 처리 card's own job; `analysis.cancel` uses `cancelTarget`). */
export async function cancelAnalysisJob(
  queryClient: QueryClient,
  runId: string,
  job: Pick<AnalysisState, "analysis_id" | "kind">,
): Promise<void> {
  await cancelAnalysis(runId, job.analysis_id);
  announce(`${kindLabel(job.kind)} 분석 취소를 요청했습니다`);
  await queryClient.invalidateQueries({ queryKey: analysesQueryKey(runId) });
}

/** Open a node's results on one job in 탐색 (`#/case/{run}/explore/analysis/{node}?id=`). */
export function openAnalysis(runId: string, kind: string, analysisId?: string): void {
  const node = nodeOfKind(kind)?.id ?? kind;
  useAppStore.getState().navigate({
    runId,
    collection: "analysis",
    kind: node,
    ...(analysisId ? { analysisId } : {}),
  });
}

export function analysisCommands(queryClient: QueryClient): Command[] {
  const runs: Command[] = ANALYSIS_KINDS.map((kind) => ({
    id: runCommandId(kind),
    label: `${kindLabel(kind)} 실행…`,
    group: "case",
    icon: "play",
    disabledReason: (ctx) => runDisabledReason(kind, ctx),
    run: () => useAnalysisStore.getState().openDialog({ kind }),
  }));
  const fromSnapshot = (kind: "vsc-compare" | "vsc-extract", label: string): Command => ({
    id: `analysis.snapshot.${kind === "vsc-compare" ? "compare" : "extract"}`,
    label,
    group: "case",
    icon: "play",
    disabledReason: (ctx) =>
      runDisabledReason(kind, ctx) ?? (focusedSnapshotRoot() ? undefined : NO_SNAPSHOT_ROW_REASON),
    run: () =>
      useAnalysisStore.getState().openDialog({ kind, preset: { snapshot_root: focusedSnapshotRoot() } }),
  });
  return [
    ...runs,
    fromSnapshot("vsc-compare", "선택한 스냅샷 비교…"),
    fromSnapshot("vsc-extract", "선택한 스냅샷 추출…"),
    {
      id: "analysis.cancel",
      label: "분석 취소",
      group: "case",
      icon: "stop",
      disabledReason: (ctx) => {
        if (!ctx.runId) return NO_RUN_REASON;
        return cancelTarget(ctx.runId) ? undefined : NOTHING_RUNNING_REASON;
      },
      run: async (ctx) => {
        const job = cancelTarget(ctx.runId);
        if (!ctx.runId || !job) return;
        await cancelAnalysisJob(queryClient, ctx.runId, job);
      },
    },
    {
      id: "analysis.openLast",
      label: "마지막 분석 결과 열기",
      group: "navigate",
      icon: "list",
      disabledReason: (ctx) => {
        if (!ctx.runId) return NO_RUN_REASON;
        return analysesFor(ctx.runId).length ? undefined : NO_ANALYSIS_REASON;
      },
      run: (ctx) => {
        // The newest COMPLETED job (its rows are final); else the running one; else the newest.
        const jobs = analysesFor(ctx.runId);
        const last = jobs.find((job) => job.status === "completed") ?? jobs.find(isAnalysisActive) ?? jobs[0];
        if (!ctx.runId || !last) return;
        openAnalysis(ctx.runId, last.kind, last.analysis_id);
        focusGridWhenReady();
      },
    },
  ];
}

export function registerAnalysisCommands(queryClient: QueryClient): () => void {
  return registerCommands(analysisCommands(queryClient));
}
