/**
 * Histogram → filter bar contract (S9 → S8).
 *
 * Time range: `window.dispatchEvent(new CustomEvent("rapidtriage:filter",
 * { detail: { from, to } }))`. `from`/`to` are ISO-8601 UTC instants, both
 * inclusive (`to` = bucket end − 1 ms). A detail without both bounds clears
 * the range. S8's filter store (features/filters/filterStore.ts) listens for
 * this event and writes `from=`/`to=` into the route (replace), so the grid,
 * the filter bar chips and the URL all follow; `setTimeRange()` is the same
 * action for callers that prefer a direct store call.
 *
 * Category bars do NOT use the event (S8 treats a detail without bounds as
 * "clear the range"); they patch the filter store directly: artifact types →
 * `types`, file extensions → `ext`.
 */

import { useFilterStore } from "../filters/filterStore";

export const VIEW_FILTER_EVENT = "rapidtriage:filter";

export interface TimeRangeFilterDetail {
  from: string | null;
  to: string | null;
}

/** Emit a time-range filter (both null = clear). Returns the dispatched detail. */
export function emitTimeRangeFilter(from: string | null, to: string | null): TimeRangeFilterDetail {
  const detail: TimeRangeFilterDetail = { from, to };
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent<TimeRangeFilterDetail>(VIEW_FILTER_EVENT, { detail }));
  }
  return detail;
}

/** Artifact-type bar → S8 `types` filter (a second click on the same single type clears it). */
export function toggleTypeFilter(type: string): boolean {
  const store = useFilterStore.getState();
  const active = store.filters.types.length === 1 && store.filters.types[0] === type;
  store.patchFilters({ types: active ? [] : [type] });
  return !active;
}

/** Extension bar → S8 `ext` filter (toggle, like the type bars). */
export function toggleExtFilter(ext: string): boolean {
  const store = useFilterStore.getState();
  const active = store.filters.ext.length === 1 && store.filters.ext[0] === ext;
  store.patchFilters({ ext: active ? [] : [ext] });
  return !active;
}
