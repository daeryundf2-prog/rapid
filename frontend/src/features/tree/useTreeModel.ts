import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { getReviewCounts, listSavedSearches } from "../../api/caseDb";
import { getRunDashboard } from "../../api/dashboard";
import { getRunSummary, getRunTree } from "../../api/runs";
import { useAnalyses } from "../analysis/store";
import { useSearchState } from "../case/searchState";
import { navigate, useRunLive } from "./adapter";
import { buildTreeModel, type TreeModelNode } from "./model";

/**
 * Live data behind the tree. Counts refresh every 3 s while the run is active
 * (the run list itself comes from `useRunLive`, which S1 backs with its shared
 * progress store, so this adds no poller of its own for run state).
 */
export function useTreeData(runId: string | null) {
  const live = useRunLive(runId);
  const refetchInterval = live.active ? 3000 : false;
  const enabled = Boolean(runId);
  const summary = useQuery({
    queryKey: ["run-summary", runId],
    queryFn: () => getRunSummary(runId as string),
    enabled,
    retry: false,
    refetchInterval,
  });
  const tree = useQuery({
    queryKey: ["run-tree", runId],
    queryFn: () => getRunTree(runId as string),
    enabled,
    retry: false,
    refetchInterval,
  });
  const review = useQuery({
    queryKey: ["review-counts", runId],
    queryFn: () => getReviewCounts(runId as string),
    enabled,
    retry: false,
    refetchInterval,
  });
  // Shared with the 접수 dashboard (same query key): evidence source + partitions.
  const dashboard = useQuery({
    queryKey: ["run-dashboard", runId],
    queryFn: () => getRunDashboard(runId as string),
    enabled,
    retry: false,
    refetchInterval,
  });
  const database = review.data?.exists ? review.data.database : null;
  const caseId = review.data?.case_id ?? null;
  const saved = useQuery({
    queryKey: ["saved-searches", runId, database],
    queryFn: () => listSavedSearches(database as string, caseId as string),
    enabled: Boolean(database && caseId),
    retry: false,
  });
  const analyses = useAnalyses(runId);
  return {
    live,
    analyses: analyses.unavailable || analyses.loading ? undefined : analyses.analyses,
    summary: summary.data,
    tree: tree.data,
    review: review.data,
    saved: saved.data,
    evidence: dashboard.data?.evidence_source,
    /** First load of the counts/tree (X18 loading card); false once either settles. */
    loading: enabled && summary.isPending && tree.isPending,
    /**
     * Every source of the hidden-family count (U-F7) answered (or failed): `/tree`, the run
     * summary and the analysis jobs — before that n would still move.
     */
    treeSettled: !enabled || (!tree.isPending && !summary.isPending && !analyses.loading),
  };
}

export function useTreeModel(runId: string | null): TreeModelNode[] {
  return useTreeState(runId).model;
}

/** Tree nodes plus the first-load flag (EvidenceTree shows a loading line, X18). */
export function useTreeState(runId: string | null): {
  model: TreeModelNode[];
  loading: boolean;
  treeSettled: boolean;
} {
  const data = useTreeData(runId);
  const applySavedSearch = useSearchState((s) => s.applySaved);
  const model = useMemo(
    () =>
      buildTreeModel({
        summary: data.summary,
        tree: data.tree,
        review: data.review,
        saved: data.saved,
        live: data.live,
        evidence: data.evidence,
        analyses: data.analyses,
        onOpenSavedSearch: (search) => {
          applySavedSearch(search);
          if (runId) navigate({ runId, collection: "search" });
        },
      }),
    [
      data.summary,
      data.tree,
      data.review,
      data.saved,
      data.live,
      data.evidence,
      data.analyses,
      applySavedSearch,
      runId,
    ],
  );
  return { model, loading: data.loading, treeSettled: data.treeSettled };
}
