// Shared react-query policy (R8 T-130): which failures are retried and when polls run.
//
// A 4xx is the server's answer, not a hiccup: asking again returns the same 400/404/409, so only
// 408 (request timeout) and 429 (too many requests) are retried among them. 5xx and fetch
// failures (`ApiError.status === 0`: network, timeout) get two more tries.
// Polls send nothing while the document is hidden: react-query's interval timer keeps running but
// skips the fetch unless `refetchIntervalInBackground` is true (query-core queryObserver), and a
// stale query refetches when the tab is visible again (`refetchOnWindowFocus`). The interval is
// never switched off for a hidden tab: a fetch that lands while hidden would clear the timer and
// leave the poll off after a short hide (adversarial review WB-5..7, T-130).

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

/** Poll options of a query: interval fetches only while the document is visible (T-130). */
export const VISIBLE_ONLY_POLL = { refetchIntervalInBackground: false } as const;

/**
 * Data another window can change (the review map, r8 T-131): refetch whenever the tab becomes
 * visible again, even inside its `staleTime` — still nothing while hidden (T-130).
 */
export const REFETCH_ON_RETURN = { refetchOnWindowFocus: "always" } as const;

/**
 * Calls `listener` when this window gets focus back while visible. react-query v5 only watches
 * `visibilitychange`, which never fires when the analyst switches between two visible browser
 * windows (T-131: the 다른 창 toast then waited for the next own mark). Returns the unsubscribe.
 */
export function onWindowReturn(listener: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  const handler = () => {
    if (typeof document === "undefined" || document.visibilityState !== "hidden") listener();
  };
  window.addEventListener("focus", handler);
  return () => window.removeEventListener("focus", handler);
}
