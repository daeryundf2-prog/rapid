/**
 * Rows for the explorer views: the same collection query (and cache entry)
 * as the DataGrid, narrowed by a view predicate and the S8 filter bar.
 */

import { useQuery } from "@tanstack/react-query";
import { type RefObject, useEffect, useMemo, useState } from "react";
import { getRunTree } from "../../api/runs";
import type { CollectionQuery, GridRow } from "../../contracts/collection";
import { useTimezone } from "../../state/hooks";
import {
  applyFiltersToQuery,
  clientOnlyFilters,
  partitionFilters,
  rowMatchesFilters,
} from "../filters/filterModel";
import { useFilterStore } from "../filters/filterStore";
import { useRoute } from "../grid/adapter";
import { matchesFilter } from "../grid/gridUtils";
import { type CollectionQueryResult, PAGE_SIZE, useCollectionQuery } from "../grid/useCollectionQuery";
import {
  artifactKindsOfTree,
  fetchGeoClusters,
  type GeoClustersPayload,
  geoTextFilterClientSide,
} from "./geo";

export interface ViewRowsOptions {
  /** Keep only rows the view can draw (images, message rows…); must be a stable function. */
  predicate: (row: GridRow) => boolean;
  /** Apply the grid's text filter `q` (server path filter + client text match). Chat only highlights. */
  textFilter: boolean;
  /** Server row conditions of the view itself (지도: `geo=` world box = located rows only); stable object. */
  rowConditions?: Record<string, string | string[]>;
  /** Server page size (default `PAGE_SIZE`; the map's coordinate table pages 500 rows). */
  pageSize?: number;
  /** Prefetch the page after the requested one (default true; the map asks one page per click). */
  prefetchNext?: boolean;
}

export interface ViewRows {
  cq: CollectionQueryResult;
  rows: GridRow[];
  runId: string | null;
  q: string;
}

export function useViewRows({
  predicate,
  textFilter,
  rowConditions,
  pageSize,
  prefetchNext,
}: ViewRowsOptions): ViewRows {
  const route = useRoute();
  const q = route.q;
  const isSearch = route.collection.id === "search";
  const cq = useCollectionQuery(
    {
      ref: route.collection,
      offset: 0,
      limit: pageSize ?? PAGE_SIZE,
      text: textFilter && q ? q : undefined,
      search: route.search,
      ...(rowConditions ? { rowConditions } : {}),
    },
    { runId: route.runId, ...(prefetchNext === false ? { prefetchNext } : {}) },
  );
  const filters = useFilterStore((s) => s.filters);
  const { timezone } = useTimezone();
  // The rows are already filtered (server + client) by the collection query: only re-check what the
  // API did not apply, never a server condition the loaded row cannot show (e.g. an NTFS time).
  const clientFilters = useMemo(
    () => clientOnlyFilters(filters, partitionFilters(route.collection, filters, [], timezone)),
    [filters, route.collection, timezone],
  );
  const rows = useMemo(
    () =>
      cq.loadedRows.filter(
        (row) =>
          predicate(row) &&
          rowMatchesFilters(row, clientFilters, timezone) &&
          (!textFilter || isSearch || matchesFilter(row, q)),
      ),
    [cq.loadedRows, predicate, clientFilters, timezone, textFilter, isSearch, q],
  );
  return { cq, rows, runId: route.runId, q };
}

/** Re-request interval while the server builds a run's located-row index (`geo_index: building`). */
export const GEO_INDEX_POLL_MS = 1000;
/** Polling of a `building` index stops after this long (then the view keeps the loaded-row clusters). */
export const GEO_INDEX_POLL_LIMIT_MS = 5 * 60_000;

export interface GeoClustersState {
  /** The server's clusters (null while loading, on error, off an artifacts node, or client-filtered). */
  payload: GeoClustersPayload | null;
  error: Error | null;
  isLoading: boolean;
  /**
   * Filters only the console applies, or a text filter the server applies only in part: the
   * server clusters cannot reflect them (no request is sent).
   */
  clientFiltered: boolean;
  /** The index was still `building` after `GEO_INDEX_POLL_LIMIT_MS`: polling stopped. */
  buildingTimedOut: boolean;
}

/**
 * Server clusters (`GET /geo-clusters`, r6 §3.3 갈래 C) for the current artifacts node with the
 * same server filters as its listing; polled while the run's located-row index is building.
 */
export function useGeoClusters({
  textFilter,
  rowConditions,
}: Pick<ViewRowsOptions, "textFilter" | "rowConditions">): GeoClustersState {
  const route = useRoute();
  const filters = useFilterStore((s) => s.filters);
  const { timezone } = useTimezone();
  const ref = route.collection;
  const query: CollectionQuery = useMemo(
    () =>
      applyFiltersToQuery(
        {
          ref,
          offset: 0,
          limit: 0,
          text: textFilter && route.q ? route.q : undefined,
          ...(rowConditions ? { rowConditions } : {}),
        },
        filters,
        [],
        timezone,
      ),
    [ref, textFilter, route.q, rowConditions, filters, timezone],
  );
  // Client-only filters, or a text filter the server sees only in part (several words, or a word
  // next to a 경로 filter): the server clusters would count other rows than the table, so the
  // view clusters its loaded rows and no cluster request is sent.
  const clientFiltered = useMemo(
    () =>
      partitionFilters(ref, filters, [], timezone).clientLabels.length > 0 || geoTextFilterClientSide(query),
    [ref, filters, timezone, query],
  );
  const isArtifacts = route.runId !== null && ref.id === "artifacts";
  // A category node sends its kinds (the run's kinds from the tree, as the listing's category
  // scope) in one request; the tree query is the shared `run-tree` cache entry.
  const category = isArtifacts && !ref.kind && Boolean(ref.category);
  const tree = useQuery({
    queryKey: ["run-tree", route.runId],
    queryFn: () => getRunTree(route.runId as string),
    enabled: category,
    retry: false,
  });
  const runKinds = useMemo(() => (tree.data ? artifactKindsOfTree(tree.data.nodes) : null), [tree.data]);
  const treeSettled = !category || tree.data !== undefined || tree.isError;
  const enabled = isArtifacts && !clientFiltered && treeSettled;
  const key = [
    "geo-clusters",
    route.runId,
    ref.kind ?? "",
    ref.kind ? "" : (ref.category ?? ""),
    JSON.stringify([
      query.pathContains ?? query.text ?? "",
      query.artifactTypes ?? [],
      query.flags ?? [],
      query.flagGrade ?? "",
      query.fields ?? {},
      query.channels ?? [],
      query.channelGroups ?? [],
      query.rowConditions ?? {},
    ]),
  ] as const;
  const keyString = JSON.stringify(key);
  const [timedOutKey, setTimedOutKey] = useState<string | null>(null);
  const timedOut = timedOutKey === keyString;
  const result = useQuery({
    queryKey: key,
    queryFn: ({ signal }) => fetchGeoClusters(route.runId as string, query, signal, runKinds),
    enabled,
    staleTime: 30_000,
    retry: false,
    refetchInterval: (q) => (q.state.data?.geo_index === "building" && !timedOut ? GEO_INDEX_POLL_MS : false),
  });
  const building = enabled && result.data?.geo_index === "building";
  // Polling stops after GEO_INDEX_POLL_LIMIT_MS of `building`: the view keeps the loaded-row
  // clusters and says so (a later visit, or the run-finish refetch, asks again).
  useEffect(() => {
    if (!building) return;
    const timer = setTimeout(() => setTimedOutKey(keyString), GEO_INDEX_POLL_LIMIT_MS);
    return () => clearTimeout(timer);
  }, [building, keyString]);
  return {
    payload: enabled ? (result.data ?? null) : null,
    error: enabled && result.error instanceof Error ? result.error : null,
    isLoading: enabled ? result.isLoading : isArtifacts && !clientFiltered,
    clientFiltered,
    buildingTimedOut: building && timedOut,
  };
}

/**
 * Keep loading pages while `wanted` is true, up to `maxRows` loaded rows
 * (then the view offers an explicit "더 불러오기").
 */
export function useAutoLoad(cq: CollectionQueryResult, wanted: boolean, maxRows: number): boolean {
  const capped = cq.loadedCount >= maxRows;
  const shouldLoad = wanted && !capped && cq.canLoadMore && !cq.isFetching && !cq.error;
  useEffect(() => {
    if (shouldLoad) cq.loadMore();
  }, [shouldLoad, cq.loadMore]);
  return capped && cq.canLoadMore;
}

/** Content width of an element (ResizeObserver), `fallback` before the first measure / in jsdom. */
export function useElementWidth(ref: RefObject<HTMLElement | null>, fallback: number): number {
  const [width, setWidth] = useState(fallback);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const measure = () => {
      const next = element.clientWidth;
      if (next > 0) setWidth(next);
    };
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, [ref]);
  return width;
}
