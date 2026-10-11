import { useQuery } from "@tanstack/react-query";
import { getReviewCounts, listSavedSearches } from "../../api/caseDb";
import { ApiError, api } from "../../api/client";
import { getCaseNotes, getRunDashboard } from "../../api/dashboard";
import { getRunIssues, getRunSummary, getRunTree, type RunJob } from "../../api/runs";
import { ACTIVE_POLL_MS } from "../../api/runsProgress";
import { isRunActive } from "../../state/slices/runs";
import type { ProgressLike } from "./model";

export interface ProviderProgress {
  status?: string;
  duration_ms?: number | null;
  artifact_count?: number | null;
}

export interface RunProgressFull extends ProgressLike {
  providers?: Record<string, ProviderProgress>;
  completed_count?: number;
  total_count?: number;
  error_count?: number;
  error?: { stage?: string; message?: string; code?: string } | null;
}

export type RunDetail = RunJob & { progress?: RunProgressFull | null };

const enc = encodeURIComponent;

/** Every query behind the dashboard; keys are shared with the tree (summary/tree/review/dashboard). */
export function useDashboardData(runId: string) {
  const detail = useQuery({
    queryKey: ["run-detail", runId],
    queryFn: () => api<RunDetail>(`/api/runs/${enc(runId)}`),
    refetchInterval: (q) => (isRunActive(q.state.data) ? ACTIVE_POLL_MS : false),
  });
  const completed = detail.data?.status === "completed";
  const summary = useQuery({
    queryKey: ["run-summary", runId],
    queryFn: () => getRunSummary(runId),
    enabled: completed,
    retry: (count, error) => count < 1 && !(error instanceof ApiError && error.status === 409),
  });
  const tree = useQuery({
    queryKey: ["run-tree", runId],
    queryFn: () => getRunTree(runId),
    enabled: completed,
    retry: false,
  });
  const review = useQuery({
    queryKey: ["review-counts", runId],
    queryFn: () => getReviewCounts(runId),
    enabled: completed,
    retry: false,
  });
  const database = review.data?.exists ? review.data.database : null;
  const caseId = review.data?.case_id ?? null;
  const saved = useQuery({
    queryKey: ["saved-searches", runId, database],
    queryFn: () => listSavedSearches(database as string, caseId as string),
    enabled: Boolean(database && caseId),
    retry: false,
  });
  const dashboard = useQuery({
    queryKey: ["run-dashboard", runId],
    queryFn: () => getRunDashboard(runId),
    retry: false,
    // Re-read once the run completes (partitions / exports appear then).
    refetchInterval: () => (isRunActive(detail.data) ? ACTIVE_POLL_MS : false),
  });
  const notes = useQuery({
    queryKey: ["case-notes", runId],
    queryFn: () => getCaseNotes(runId),
    retry: false,
  });
  const issues = useQuery({
    queryKey: ["run-issues", runId],
    queryFn: () => getRunIssues(runId),
    enabled: completed,
    retry: false,
  });
  return { detail, completed, summary, tree, review, saved, dashboard, notes, issues };
}

export type DashboardData = ReturnType<typeof useDashboardData>;
