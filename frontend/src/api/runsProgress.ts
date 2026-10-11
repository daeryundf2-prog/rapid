// GET /api/runs with the compact `progress` block (routes_runs.compact_run_progress),
// polled every 1.5 s while any run is queued/running and every 5 s when idle.

import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { useAppStore } from "../state/store";
import { api } from "./client";
import type { RunListItem } from "./runs";

export interface RunProgressCompact {
  status?: string | null;
  stage?: string | null;
  completed_count?: number | null;
  total_count?: number | null;
  error_count?: number | null;
  /** Provider kinds currently running. */
  running?: string[];
  updated_at?: string | null;
}

export interface RunWithProgress extends RunListItem {
  /** Present only for queued/running runs. */
  progress?: RunProgressCompact | null;
  error?: string;
}

export const RUNS_QUERY_KEY = ["runs"] as const;
export const ACTIVE_POLL_MS = 1500;
export const IDLE_POLL_MS = 5000;

export async function listRunsWithProgress(): Promise<RunWithProgress[]> {
  const payload = await api<{ runs?: RunWithProgress[] }>("/api/runs");
  return Array.isArray(payload.runs) ? payload.runs : [];
}

export function runsPollInterval(runs: readonly RunWithProgress[] | undefined): number {
  return runs?.some((r) => r.status === "queued" || r.status === "running") ? ACTIVE_POLL_MS : IDLE_POLL_MS;
}

/**
 * The one runs poller. Every caller shares the same react-query entry, so
 * mounting it in several places still polls once; the result is mirrored into
 * the app store (`useRuns()` in state/hooks) for the command context.
 */
export function useRunsPoll() {
  const query = useQuery({
    queryKey: RUNS_QUERY_KEY,
    queryFn: listRunsWithProgress,
    refetchInterval: (q) => runsPollInterval(q.state.data),
  });
  const { data, isError } = query;
  useEffect(() => {
    if (data) useAppStore.getState().setRuns(data);
  }, [data]);
  useEffect(() => {
    if (isError) useAppStore.getState().setRunsStatus("error");
  }, [isError]);
  return query;
}
