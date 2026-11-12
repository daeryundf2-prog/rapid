// Shared react-query policy (R8 T-130): which failures are retried and when polls run.
//
// A 4xx is the server's answer, not a hiccup: asking again returns the same 400/404/409, so only
// 408 (request timeout) and 429 (too many requests) are retried among them. 5xx and fetch
// failures (`ApiError.status === 0`: network, timeout) get two more tries.
// Polls stop while the document is hidden (`visibilitychange`); react-query refetches stale
// queries when the tab becomes visible again (`refetchOnWindowFocus`), which re-arms the poll.

import { focusManager } from "@tanstack/react-query";

/** Retries after the first failure, for 5xx / network failures and 408 / 429. */
export const MAX_QUERY_RETRIES = 2;

/** 4xx statuses that are worth asking again. */
const RETRYABLE_4XX: ReadonlySet<number> = new Set([408, 429]);

function errorStatus(error: unknown): number | null {
  if (error instanceof Error && "status" in error) {
    const status = (error as { status: unknown }).status;
    if (typeof status === "number") return status;
  }
  return null;
}

/** The default `retry` of every query: never a 4xx (except 408 / 429), at most two otherwise. */
export function shouldRetryQuery(failureCount: number, error: unknown): boolean {
  const status = errorStatus(error);
  if (status !== null && status >= 400 && status < 500 && !RETRYABLE_4XX.has(status)) return false;
  return failureCount < MAX_QUERY_RETRIES;
}

/** True while the document is visible (react-query's own focus/visibility state). */
export function isDocumentVisible(): boolean {
  return focusManager.isFocused();
}

/** `ms` while the document is visible, `false` (no poll) while it is hidden. */
export function pollWhenVisible(ms: number | false): number | false {
  return ms !== false && isDocumentVisible() ? ms : false;
}
