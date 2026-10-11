// Run lifecycle controls used by the status bar (plan §4.3 상태바 row).

import { api } from "./client";
import type { RunJob } from "./runs";

/** POST /api/runs/{id}/cancel */
export function cancelRun(runId: string): Promise<RunJob> {
  return api<RunJob>(`/api/runs/${encodeURIComponent(runId)}/cancel`, { method: "POST" });
}

/** POST /api/runs/{id}/retry — 409 when the run cannot be retried. */
export function retryRun(runId: string): Promise<RunJob> {
  return api<RunJob>(`/api/runs/${encodeURIComponent(runId)}/retry`, { method: "POST" });
}
