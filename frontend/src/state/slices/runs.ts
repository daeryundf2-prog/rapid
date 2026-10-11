import type { StateCreator } from "zustand";
import type { RunWithProgress } from "../../api/runsProgress";
import type { AppState } from "../store";

export const ACTIVE_RUN_STATUSES: ReadonlySet<string> = new Set(["queued", "running"]);

export interface RunsSlice {
  /** Latest GET /api/runs payload (kept fresh by `useRunsPoll`). */
  runs: RunWithProgress[];
  runsStatus: "loading" | "ok" | "error";
  setRuns: (runs: RunWithProgress[]) => void;
  setRunsStatus: (status: RunsSlice["runsStatus"]) => void;
}

export const createRunsSlice: StateCreator<AppState, [], [], RunsSlice> = (set) => ({
  runs: [],
  runsStatus: "loading",
  setRuns: (runs) => set({ runs, runsStatus: "ok" }),
  setRunsStatus: (runsStatus) => set({ runsStatus }),
});

export function isRunActive(run: { status?: unknown } | null | undefined): boolean {
  return !!run && ACTIVE_RUN_STATUSES.has(String(run.status));
}

export function currentRun(state: Pick<AppState, "route" | "runs">): RunWithProgress | null {
  const { runId } = state.route;
  return runId ? (state.runs.find((r) => r.run_id === runId) ?? null) : null;
}

export function anyRunActive(state: Pick<AppState, "runs">): boolean {
  return state.runs.some(isRunActive);
}
