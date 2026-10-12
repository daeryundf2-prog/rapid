/**
 * Analysis workbench state shared by the tree, the pane, the progress chip and the
 * commands: the run's job list (mirrored from the `["analyses", runId]` query) and the
 * open run dialog. Commands read it through `getState()` (no React).
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { create } from "zustand";
import { announce } from "../../a11y";
import { type AnalysisKind, type AnalysisState, isAnalysisActive, listAnalyses } from "../../api/analyses";
import { ApiError } from "../../api/client";
import { kindLabel, STATUS_LABEL } from "./kinds";

/** Poll interval while any job of the run is queued/running (plan §4: 1 s). */
export const ANALYSIS_POLL_MS = 1000;

export const ANALYSES_UNAVAILABLE_REASON = "이 서버는 분석 작업을 지원하지 않습니다";

export interface AnalysisDialogRequest {
  kind: AnalysisKind;
  /** Prefilled form values (e.g. the snapshot picked from discover results). */
  preset?: Record<string, string | boolean | string[]>;
}

interface AnalysisStoreState {
  runId: string | null;
  analyses: AnalysisState[];
  /** False when the server has no `/analyses` (404): every run command says why. */
  available: boolean;
  dialog: AnalysisDialogRequest | null;
  setSnapshot: (runId: string | null, analyses: AnalysisState[], available: boolean) => void;
  openDialog: (request: AnalysisDialogRequest) => void;
  closeDialog: () => void;
}

export const useAnalysisStore = create<AnalysisStoreState>((set) => ({
  runId: null,
  analyses: [],
  available: true,
  dialog: null,
  setSnapshot: (runId, analyses, available) => set({ runId, analyses, available }),
  openDialog: (request) => set({ dialog: request }),
  closeDialog: () => set({ dialog: null }),
}));

const NO_ANALYSES: AnalysisState[] = [];

export function analysesQueryKey(runId: string | null) {
  return ["analyses", runId] as const;
}

/** Jobs of the store's run (empty when the store follows another run). */
export function analysesFor(runId: string | null): AnalysisState[] {
  const s = useAnalysisStore.getState();
  return runId && s.runId === runId ? s.analyses : [];
}

export interface UseAnalysesOptions {
  /**
   * Owner of the 1 s poll (the status-bar chip). Other readers share the same query and
   * never poll on their own, so one interval runs per run.
   */
  poll?: boolean;
}

/**
 * `GET /api/runs/{run}/analyses`. With `poll`, refetches every second while any job is
 * queued/running and stops when none is (and when the owner unmounts).
 */
export function useAnalyses(runId: string | null, options: UseAnalysesOptions = {}) {
  const query = useQuery({
    queryKey: analysesQueryKey(runId),
    queryFn: ({ signal }) => listAnalyses(runId as string, signal),
    enabled: Boolean(runId),
    retry: false,
    // Several readers mount together (tree, pane, chip): one request, then the chip's poll.
    staleTime: 500,
    refetchInterval: options.poll
      ? (q: { state: { data?: AnalysisState[] } }) =>
          q.state.data?.some(isAnalysisActive) ? ANALYSIS_POLL_MS : false
      : false,
    refetchIntervalInBackground: true,
  });
  const unavailable =
    query.error instanceof ApiError && (query.error.status === 404 || query.error.status === 405);
  const data = query.data;
  // Re-render once the store mirrors this data: command buttons below compute their disabled
  // reasons from the store (commands have no React context of their own).
  useAnalysisStore((s) => s.analyses);
  useEffect(() => {
    if (!runId) return;
    useAnalysisStore.getState().setSnapshot(runId, data ?? [], !unavailable);
  }, [runId, data, unavailable]);
  return {
    analyses: data ?? NO_ANALYSES,
    loading: query.isPending && Boolean(runId),
    unavailable,
    error: query.error && !unavailable ? query.error : null,
    refetch: query.refetch,
  };
}

/**
 * Poll owner side effects: when a job settles (running → completed/failed/cancelled)
 * announce it once and refresh what it feeds (its rows, the tree, the files NTFS join).
 * A job first seen already settled (it started and finished between two polls) is a
 * transition too; only the first loaded snapshot of a run (history) is not news.
 * While a job runs, its partial rows are refreshed whenever its row count grows.
 * `loaded: false` (query still pending) leaves the baseline unset.
 */
export function useAnalysisTransitions(
  runId: string | null,
  analyses: readonly AnalysisState[],
  { loaded = true }: { loaded?: boolean } = {},
): void {
  const queryClient = useQueryClient();
  const previous = useRef<Map<string, AnalysisState> | null>(null);
  const previousRun = useRef<string | null>(null);
  useEffect(() => {
    if (previousRun.current !== runId) {
      previousRun.current = runId;
      previous.current = null;
    }
    if (!loaded) return;
    const before = previous.current;
    previous.current = new Map(analyses.map((a) => [a.analysis_id, a]));
    if (!before || !runId) return; // first snapshot of a run is not news
    let refreshRows = false;
    let refreshFeeds = false;
    for (const job of analyses) {
      const old = before.get(job.analysis_id);
      // A job new since the last poll is news only once settled (a running one is announced
      // when it settles); one first seen already settled ran entirely between two polls.
      const settled = !isAnalysisActive(job) && (!old || isAnalysisActive(old));
      if (settled) {
        const count = job.status === "completed" ? ` · ${job.row_count.toLocaleString("ko-KR")}건` : "";
        announce(`${kindLabel(job.kind)} 분석 ${STATUS_LABEL[job.status]}${count}`, {
          politeness: job.status === "failed" ? "assertive" : "polite",
        });
        refreshRows = true;
        refreshFeeds = true;
      } else if (!old) {
        // new and still queued/running: nothing to announce yet
      } else if (old.status === "queued" && job.status === "running") {
        announce(`${kindLabel(job.kind)} 분석을 시작했습니다`);
      } else if (job.row_count !== old.row_count) {
        refreshRows = true;
      }
    }
    if (refreshRows) {
      void queryClient.invalidateQueries({ queryKey: ["collection", runId, "analysis"] });
    }
    if (refreshFeeds) {
      void queryClient.invalidateQueries({ queryKey: ["run-tree", runId] });
      void queryClient.invalidateQueries({ queryKey: ["collection", runId, "files"] });
    }
  }, [runId, analyses, loaded, queryClient]);
}
