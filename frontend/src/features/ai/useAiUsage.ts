/**
 * AI 사용 data hooks (R7 단계 3.5 갈래 D): the run's small AI row types, read once per run and
 * shared by the tree (도구·설치 facets) and the 접수 card (AI 사용 요약). Nothing is requested for
 * a run without `ai-agent` rows.
 */

import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { fetchAiGapReport, fetchAiRows } from "../../api/aiUsage";
import type { RunTree } from "../../api/runs";
import { mergedKindNode } from "../tree/model";
import { AI_SUMMARY_TYPES, presenceFacets, summarizeAiUsage } from "./aiUsage";

/** Rows the summary reads at most per request group (small types; sessions for the period). */
export const AI_SUMMARY_MAX_ROWS = 5000;
export const AI_SESSION_MAX_ROWS = 5000;

export const aiRowsQueryKey = (runId: string | null) => ["ai-usage-rows", runId] as const;
export const aiSummaryQueryKey = (runId: string | null) => ["ai-usage-summary", runId] as const;

/** Rows of the `ai-agent` kind in this run's `/tree` (0 = none, undefined = unknown). */
export function aiRowCount(tree: RunTree | undefined): number | undefined {
  if (!tree) return undefined;
  return mergedKindNode(tree, "ai-agent")?.count ?? 0;
}

/** Rows of one AI type in this run's `/tree`. */
export function aiTypeCount(tree: RunTree | undefined, type: string): number | undefined {
  if (!tree) return undefined;
  const counts = mergedKindNode(tree, "ai-agent")?.artifact_type_counts;
  return counts ? (counts[type] ?? 0) : mergedKindNode(tree, "ai-agent") ? undefined : 0;
}

/** The small row types (presence, credentials, accounts, switches, retention) of a run. */
export function useAiSmallRows(runId: string | null, enabled: boolean) {
  return useQuery({
    queryKey: aiRowsQueryKey(runId),
    queryFn: ({ signal }) => fetchAiRows(runId as string, AI_SUMMARY_TYPES, AI_SUMMARY_MAX_ROWS, signal),
    enabled: Boolean(runId) && enabled,
    retry: false,
    staleTime: 5 * 60_000,
  });
}

/**
 * 도구·설치 facets for the tree: `{"ai-agent": {...}}` once the presence rows are read, `{}`-valued
 * when the run has no presence rows, undefined while unknown.
 */
export function useAiRowFacets(
  runId: string | null,
  tree: RunTree | undefined,
  active: boolean,
): Record<string, Record<string, number>> | undefined {
  const presence = aiTypeCount(tree, "ai-tool-presence");
  const rows = useAiSmallRows(runId, !active && (presence ?? 0) > 0);
  const data = rows.data;
  return useMemo(() => {
    if (presence === 0) return { "ai-agent": presenceFacets([]) };
    return data ? { "ai-agent": presenceFacets(data.rows) } : undefined;
  }, [presence, data]);
}

/** AI 사용 요약 of the 접수 card (enabled only when the run has AI rows). */
export function useAiUsageSummary(runId: string | null, tree: RunTree | undefined) {
  const enabled = (aiRowCount(tree) ?? 0) > 0;
  const small = useAiSmallRows(runId, enabled);
  return useQuery({
    queryKey: aiSummaryQueryKey(runId),
    queryFn: async ({ signal }) => {
      const id = runId as string;
      const [sessions, gap] = await Promise.all([
        fetchAiRows(id, ["ai-agent-session"], AI_SESSION_MAX_ROWS, signal),
        fetchAiGapReport(id, signal).catch(() => null),
      ]);
      const rows = small.data ?? (await fetchAiRows(id, AI_SUMMARY_TYPES, AI_SUMMARY_MAX_ROWS, signal));
      return summarizeAiUsage({
        rows: rows.rows,
        sessions: sessions.rows,
        sessionsCapped: sessions.truncated,
        truncated: rows.truncated,
        gap,
      });
    },
    enabled: Boolean(runId) && enabled && !small.isPending,
    retry: false,
    staleTime: 5 * 60_000,
  });
}
