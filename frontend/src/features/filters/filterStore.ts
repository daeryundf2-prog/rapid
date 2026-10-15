/**
 * Filter store (X19). The URL route is the source of truth (`from`, `to`,
 * `status`, `types`, `tags`, `ext`, `path`); this zustand mirror gives hooks a
 * cheap subscription and lets non-React callers (S9's histogram) set a range.
 *
 *  - `setFilters`/`setTimeRange` write the route (replace, so filtering does not
 *    fill history) and the mirror follows the route subscription.
 *  - `rapidtriage:filter` CustomEvent `{from, to}` (S9 histogram drag) sets the
 *    time range; a detail without both bounds clears it.
 *  - `report` is published by useCollectionQuery for the status line.
 */

import { create } from "zustand";
import type { Route } from "../../router";
import { useAppStore } from "../../state/store";
import {
  EMPTY_FILTERS,
  type FilterState,
  filtersEqual,
  filtersFromRoute,
  filtersToRoutePatch,
  normalizeExt,
} from "./filterModel";

export interface FilterReport {
  serverLabels: string[];
  clientLabels: string[];
  /** Rows loaded from the server before client filters. */
  loaded: number;
  /** Rows after client filters. */
  shown: number;
  /** Total reported by the server (null = unknown). */
  serverTotal: number | null;
  /** More rows exist on the server than were loaded/scanned for client filtering. */
  capped: boolean;
  /** The API flagged the result as truncated. */
  truncated: boolean;
  /** Navigation scope line (category nodes: "범주: 운영 체제 (5 유형)"). */
  scope?: string;
  /** Server-filtered count (`matched`); null = not known yet ("n건 이상"). */
  matched?: number | null;
}

interface FilterStoreState {
  filters: FilterState;
  report: FilterReport | null;
  /** Artifact types / tags present in the loaded rows (filter bar choices). */
  typeOptions: string[];
  tagOptions: string[];
  /** Loaded (unfiltered) rows per artifact type: the 유형 list's right-aligned counts. */
  typeCounts: Record<string, number>;
  setOptions: (types: string[], tags: string[], counts?: Record<string, number>) => void;
  setFilters: (next: FilterState) => void;
  patchFilters: (patch: Partial<FilterState>) => void;
  clearFilters: () => void;
  setReport: (report: FilterReport | null) => void;
}

function writeRoute(next: FilterState): void {
  useAppStore.getState().patchRoute(filtersToRoutePatch(next), { replace: true });
}

export const useFilterStore = create<FilterStoreState>((set, get) => ({
  filters: filtersFromRoute(useAppStore.getState().route),
  report: null,
  typeOptions: [],
  tagOptions: [],
  typeCounts: {},
  setOptions: (types, tags, counts = {}) => {
    const s = get();
    if (
      s.typeOptions.join("\u0000") === types.join("\u0000") &&
      s.tagOptions.join("\u0000") === tags.join("\u0000") &&
      JSON.stringify(s.typeCounts) === JSON.stringify(counts)
    )
      return;
    set({ typeOptions: types, tagOptions: tags, typeCounts: counts });
  },
  setFilters: (next) => {
    const clean: FilterState = { ...next, ext: next.ext.map(normalizeExt).filter(Boolean) };
    if (filtersEqual(clean, get().filters)) return;
    set({ filters: clean }); // immediate; the route subscription re-confirms it
    writeRoute(clean);
  },
  patchFilters: (patch) => get().setFilters({ ...get().filters, ...patch }),
  clearFilters: () => get().setFilters(EMPTY_FILTERS),
  setReport: (report) => {
    const prev = get().report;
    if (prev === report || (prev && report && JSON.stringify(prev) === JSON.stringify(report))) return;
    set({ report });
  },
}));

/** Store-level range setter for other streams (histogram brush, timeline view). */
export function setTimeRange(from: string | undefined, to: string | undefined): void {
  useFilterStore.getState().patchFilters({ from: from || undefined, to: to || undefined });
}

let lastRoute: Route | null = null;
useAppStore.subscribe((state) => {
  if (state.route === lastRoute) return;
  lastRoute = state.route;
  const next = filtersFromRoute(state.route);
  if (!filtersEqual(next, useFilterStore.getState().filters)) useFilterStore.setState({ filters: next });
});

export const FILTER_EVENT = "rapidtriage:filter";

export interface FilterEventDetail {
  from?: string | null;
  to?: string | null;
}

/** Handle a `rapidtriage:filter` event: both bounds set a range, anything else clears it. */
export function handleFilterEvent(event: Event): void {
  const detail = (event as CustomEvent<FilterEventDetail | undefined>).detail;
  const from = typeof detail?.from === "string" && detail.from ? detail.from : undefined;
  const to = typeof detail?.to === "string" && detail.to ? detail.to : undefined;
  setTimeRange(from, to);
}

if (typeof window !== "undefined") window.addEventListener(FILTER_EVENT, handleFilterEvent);
