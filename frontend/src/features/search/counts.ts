/**
 * Search counts, asked apart from the result pages (plan search-2026-10-13 §7: the first page
 * never waits for totals). One request per search, cached by its text, so adding a chip or
 * switching between chips never recounts the others.
 */

import { useQueries, useQuery } from "@tanstack/react-query";
import type { CollectionQuery } from "../../contracts/collection";
import { countSearch, getSearchIndexStatus, type SearchCount, type SearchIndexStatus } from "./api";
import { searchPlan } from "./queryModel";

/** Counts running at once: the server gives a run four query slots and the grid's pages need theirs. */
const MAX_COUNTS = 2;
let running = 0;
const waiting: Array<() => void> = [];

async function limited<T>(work: () => Promise<T>): Promise<T> {
  if (running < MAX_COUNTS) running += 1;
  // A finishing count hands its slot to the oldest waiter.
  else await new Promise<void>((resolve) => waiting.push(resolve));
  try {
    return await work();
  } finally {
    const next = waiting.shift();
    if (next) next();
    else running -= 1;
  }
}

export const SEARCH_COUNT_KEY = "search-count";
export const SEARCH_INDEX_KEY = "search-index";
const INDEX_POLL_MS = 1500;

/** The run's index state (one request shared by the workspace and the grid), polled while a build runs. */
export function searchIndexQuery(runId: string | null) {
  return {
    queryKey: [SEARCH_INDEX_KEY, runId] as const,
    queryFn: ({ signal }: { signal: AbortSignal }) => getSearchIndexStatus(runId ?? "", signal),
    enabled: runId !== null,
    refetchInterval: (query: { state: { data?: SearchIndexStatus } }) =>
      query.state.data?.state === "building" ? INDEX_POLL_MS : false,
    staleTime: 15_000,
    retry: false,
  };
}

/** The run to count on: null until its index can answer (a stale one, or the one a build replaces, does). */
function useCountableRun(runId: string | null): string | null {
  const index = useQuery(searchIndexQuery(runId)).data;
  const answers =
    index?.state === "ready" ||
    index?.state === "stale" ||
    index?.state === "build-failed-swap" ||
    (index?.state === "building" && index.docCount > 0);
  return answers ? runId : null;
}

function countQuery(runId: string | null, q: string | null) {
  return {
    queryKey: [SEARCH_COUNT_KEY, runId, q ?? ""] as const,
    queryFn: ({ signal }: { signal: AbortSignal }) =>
      limited(() => countSearch(runId ?? "", q ?? "", signal)),
    enabled: runId !== null && q !== null && q !== "",
    staleTime: 60_000,
    // A run without an index answers 404; asking again changes nothing.
    retry: false,
  };
}

export interface SearchCountState {
  /** The count once it arrived. */
  readonly result: SearchCount | undefined;
  readonly counting: boolean;
}

/** Counts of several index queries, in the given order. */
export function useSearchCounts(runId: string | null, queries: readonly string[]): SearchCountState[] {
  const countable = useCountableRun(runId);
  return useQueries({
    queries: queries.map((q) => countQuery(countable, q)),
    combine: (results) => results.map((r) => ({ result: r.data, counting: r.isFetching })),
  });
}

/** Total of the search grid's query (null while unknown, and for a search the scan answers). */
export function useSearchTotal(
  runId: string | null,
  query: Pick<CollectionQuery, "ref" | "search" | "extension">,
): number | null {
  const spec = query.ref.id === "search" && query.search?.keywords.length ? query.search : undefined;
  const plan = spec ? searchPlan(spec, query.extension) : null;
  const countable = useCountableRun(plan?.kind === "index" ? runId : null);
  const counted = useQuery(countQuery(countable, plan?.kind === "index" ? plan.q : null));
  return counted.data?.count ?? null;
}
