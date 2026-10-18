// Run lifecycle controls used by the status bar and the 처리 stage (plan §4.3 상태바 row, R4 V1).

import { api } from "./client";
import type { RunJob } from "./runs";

/** POST /api/runs/{id}/cancel — since R4 V1 an alias of the plan's `cancel_all`. */
export function cancelRun(runId: string): Promise<RunJob> {
  return api<RunJob>(`/api/runs/${encodeURIComponent(runId)}/cancel`, { method: "POST" });
}

export interface RetryOptions {
  /** true = 이어서 실행 (reuse completed tasks), false = 처음부터 다시. */
  resume?: boolean;
}

export type RetryResult = RunJob & { retry_mode?: "resume" | "fresh" | string };

/** POST /api/runs/{id}/retry `{resume}` — 409 unless the run failed, was cancelled or interrupted. */
export function retryRun(runId: string, options: RetryOptions = {}): Promise<RetryResult> {
  return api<RetryResult>(`/api/runs/${encodeURIComponent(runId)}/retry`, {
    method: "POST",
    body: JSON.stringify({ resume: options.resume ?? false }),
  });
}
