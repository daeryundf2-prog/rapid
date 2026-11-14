import { type QueryClient, useQuery } from "@tanstack/react-query";
import { listSavedSearches } from "../../api/caseDb";

/**
 * Case-DB saved searches change only when the examiner saves (or, later, deletes) one, so the
 * list is not refetched on every window focus (R7 S2: ~200 list requests per QA session with
 * the global 2 s staleTime). Every write must call {@link invalidateSavedSearches}.
 */
export const SAVED_SEARCHES_STALE_MS = 60_000;

export function savedSearchesKey(runId: string | null, database?: string | null): readonly unknown[] {
  return database === undefined ? ["saved-searches", runId] : ["saved-searches", runId, database];
}

/** Saved searches of the run's case DB (the dashboard and the evidence tree share this query). */
export function useSavedSearches(runId: string | null, database: string | null, caseId: string | null) {
  return useQuery({
    queryKey: savedSearchesKey(runId, database),
    queryFn: () => listSavedSearches(database as string, caseId as string),
    enabled: Boolean(database && caseId),
    retry: false,
    staleTime: SAVED_SEARCHES_STALE_MS,
    refetchOnWindowFocus: false,
  });
}

/** After a save/delete: every saved-search list of the run refetches. */
export function invalidateSavedSearches(queryClient: QueryClient, runId: string | null): Promise<void> {
  return queryClient.invalidateQueries({ queryKey: savedSearchesKey(runId) });
}
