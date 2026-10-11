import { useQueries, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError } from "../../api/client";
import type { RawPage } from "../../api/collections";
import type { CollectionQuery, GridRow, ReviewStatus } from "../../contracts/collection";
import { useTimezone } from "../../state/hooks";
import {
  applyClientFilters,
  applyFiltersToQuery,
  clientOnlyFilters,
  EMPTY_FILTERS,
  hasActiveFilters,
  partitionFilters,
} from "../filters/filterModel";
import { useFilterStore } from "../filters/filterStore";
import { categoryInfo, isArtifactCategoryId } from "../tree/categories";
import { useRoute } from "./adapter";
import { collectionDef } from "./columns";
import { serverPathFilter } from "./gridUtils";
import { overlayReview, useReviewMap } from "./reviewMap";
import type { CollectionDef } from "./types";

/** Server page size (plan: 250). */
export const PAGE_SIZE = 250;

export interface CollectionQueryOptions {
  /** Defaults to the route's run id (adapter useRoute). */
  runId?: string | null;
  /**
   * Side-collection read: ignores the shared filter bar and never publishes
   * filter options / the filter report (so it cannot clobber the main query's).
   */
  passive?: boolean;
}

export interface CollectionQueryResult {
  def: CollectionDef;
  pageSize: number;
  /** Total rows after server filters; null while unknown. */
  total: number | null;
  /** Number of server pages (1 for whole collections); null while total is unknown. */
  pageCount: number | null;
  /** Pages currently loaded. */
  pagesLoaded: number;
  loadedCount: number;
  /** Row at an index of the unfiltered collection; undefined while its page is not loaded. */
  getRow: (index: number) => GridRow | undefined;
  /** Every loaded row in collection order (client filter/sort run over this). */
  loadedRows: GridRow[];
  /** Ask for the pages covering [start, end] (+ the next page, prefetched). */
  ensureRange: (start: number, end: number) => void;
  /** Ask for the first not-yet-loaded page after the loaded ones (compact/filter mode scrolling). */
  loadMore: () => void;
  isLoading: boolean;
  isFetching: boolean;
  error: Error | null;
  refetch: () => void;
  backend: string;
  truncated: boolean;
  elapsedMs: number;
  /** True when no page has total info for server-side text filtering: text is applied to loaded rows. */
  textFilterIsClientSide: boolean;
  /** Another page exists (works when total is unknown, e.g. server-side path filter). */
  canLoadMore: boolean;
  /** Rows scanned by the server-side filter, when reported. */
  scanned: number | undefined;
  /** Optimistic patch of loaded rows (review marks); returns a rollback function. */
  patchRows: (keys: string[], patch: (row: GridRow) => GridRow) => () => void;
  /** Category node scope (artifacts `?category=`): label + the run's kinds in it (null while unknown). */
  category: { id: string; label: string; kindCount: number | null } | null;
}

/** Footer/filter status text for a category scope: "범주: 운영 체제 (5 유형)". */
export function categoryScopeText(category: NonNullable<CollectionQueryResult["category"]>): string {
  return `범주: ${category.label} (${category.kindCount ?? "-"} 유형)`;
}

/** Row mapping is memoised per raw page object (pages are immutable in the query cache). */
const mappedPages = new WeakMap<RawPage, GridRow[]>();

function mapPage(def: CollectionDef, page: RawPage, ref: CollectionQuery["ref"]): GridRow[] {
  const cached = mappedPages.get(page);
  if (cached) return cached;
  const rows = page.rows.map((raw, i) => def.mapRow(raw, page.offset + i, { ref }));
  mappedPages.set(page, rows);
  return rows;
}

function statusFilter(rows: GridRow[], status: ReviewStatus | undefined): GridRow[] {
  if (!status) return rows;
  return rows.filter((row) =>
    status === "include-in-report" ? row.fields.includeInReport === true : row.reviewStatus === status,
  );
}

export function collectionQueryKey(runId: string | null, query: CollectionQuery, pageSize: number) {
  const def = collectionDef(query.ref.id);
  return [
    "collection",
    runId,
    query.ref.id,
    query.ref.kind ?? "",
    query.ref.id === "artifacts" && !query.ref.kind ? (query.ref.category ?? "") : "",
    def.source === "whole" ? (query.search ?? null) : null,
    def.source === "whole" ? (query.extension ?? null) : null,
    query.ref.id === "artifacts" ? query.pathContains?.trim() || serverPathFilter(query.text) || "" : "",
    pageSize,
  ] as const;
}

/** Collections whose rows carry run-output locators the review map can match. */
const REVIEW_OVERLAY_COLLECTIONS: ReadonlySet<string> = new Set([
  "files",
  "docs",
  "artifacts",
  "timeline",
  "indicators",
  "search",
]);

/** Pages auto-loaded while client-side filters are active (they only see loaded rows). */
export const FILTER_AUTOLOAD_PAGES = 8;

export function useCollectionQuery(
  rawQuery: CollectionQuery,
  options: CollectionQueryOptions = {},
): CollectionQueryResult {
  const storeFilters = useFilterStore((s) => s.filters);
  const passive = options.passive === true;
  const filters = passive ? EMPTY_FILTERS : storeFilters;
  const setReport = useFilterStore((s) => s.setReport);
  useTimezone(); // timestamp cells format in the display timezone; re-render rows when it changes
  const setOptions = useFilterStore((s) => s.setOptions);
  // Server-capable filters (path_contains, kind=, extension) fold into the query; the rest stay client-side.
  // biome-ignore lint/correctness/useExhaustiveDependencies: rawQuery fields are listed individually
  const query = useMemo(
    () => applyFiltersToQuery(rawQuery, filters),
    [
      rawQuery.ref.id,
      rawQuery.ref.kind,
      rawQuery.ref.status,
      rawQuery.ref.category,
      rawQuery.text,
      rawQuery.search,
      rawQuery.extension,
      rawQuery.limit,
      rawQuery.offset,
      filters,
    ],
  );
  const plan = useMemo(() => partitionFilters(rawQuery.ref, filters), [rawQuery.ref, filters]);
  const clientFiltering = plan.clientLabels.length > 0;
  const route = useRoute();
  const runId = options.runId !== undefined ? options.runId : route.runId;
  const queryClient = useQueryClient();
  const def = collectionDef(query.ref.id);
  const pageSize = query.limit > 0 ? query.limit : PAGE_SIZE;
  const baseKey = collectionQueryKey(runId, query, pageSize);
  const keyString = JSON.stringify(baseKey);

  const [wantedState, setWantedState] = useState<{ key: string; pages: number[] }>({
    key: keyString,
    pages: [0],
  });
  const wanted = wantedState.key === keyString ? wantedState.pages : [0];

  // Page 0 always loads first; its `total` gates every later page (no speculative requests).
  const firstPass = def.source === "whole" ? [0] : wanted;
  const gateTotal = queryClient.getQueryData<RawPage>([...baseKey, "page", 0])?.total ?? null;

  const results = useQueries({
    queries: firstPass.map((p) => ({
      queryKey: [...baseKey, "page", p] as const,
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        def.fetch(runId as string, { ...query, offset: p * pageSize, limit: pageSize }, signal),
      enabled:
        runId !== null &&
        (p === 0 ||
          (gateTotal !== null
            ? p * pageSize < gateTotal
            : queryClient.getQueryData<RawPage>([...baseKey, "page", p - 1])?.hasMore === true)),
      staleTime: 30_000,
      // Client errors (4xx) will not fix themselves; server errors get one quick retry.
      retry: (count: number, error: Error) => count < 1 && !(error instanceof ApiError && error.status < 500),
      retryDelay: 300,
    })),
  });

  const pageData: (RawPage | undefined)[] = results.map((r) => r.data);
  const firstData = pageData[0];
  const total0 = pageData.find((d) => d && d.total !== null)?.total ?? gateTotal;
  const signature = `${firstPass.join(",")}|${results.map((r) => r.dataUpdatedAt).join(",")}`;

  // Stored review state (case DB) overlays rows by run-output locator; the review board is the map itself.
  const reviewMap = useReviewMap(runId, REVIEW_OVERLAY_COLLECTIONS.has(query.ref.id));

  // biome-ignore lint/correctness/useExhaustiveDependencies: `signature` tracks every page update
  const mappedByPage = useMemo(() => {
    const map = new Map<number, GridRow[]>();
    firstPass.forEach((p, i) => {
      const data = pageData[i];
      if (!data) return;
      const mapped = mapPage(def, data, rawQuery.ref);
      const rows =
        reviewMap && reviewMap.size > 0 ? mapped.map((row) => overlayReview(row, reviewMap)) : mapped;
      map.set(p, def.source === "whole" ? statusFilter(rows, rawQuery.ref.status) : rows);
    });
    return map;
  }, [def, rawQuery.ref, signature, reviewMap]);

  const [overlay, setOverlay] = useState<Map<string, (row: GridRow) => GridRow>>(new Map());
  // Patched rows are memoised per (base row, patch) so row identity is stable across renders.
  const patched = useMemo(() => new WeakMap<GridRow, { fn: (row: GridRow) => GridRow; out: GridRow }>(), []);
  const applyOverlay = useCallback(
    (row: GridRow): GridRow => {
      const fn = overlay.get(row.rowKey);
      if (!fn) return row;
      const hit = patched.get(row);
      if (hit && hit.fn === fn) return hit.out;
      const out = fn(row);
      patched.set(row, { fn, out });
      return out;
    },
    [overlay, patched],
  );

  const unfilteredRows = useMemo(() => {
    const pages = [...mappedByPage.keys()].sort((a, b) => a - b);
    const rows = pages.flatMap((p) => mappedByPage.get(p) ?? []);
    if (overlay.size === 0) return rows;
    return rows.map((row) => applyOverlay(row));
  }, [mappedByPage, overlay, applyOverlay]);

  // Client-side filters see loaded rows only; the grid then treats the result like a whole collection.
  const clientFilters = useMemo(() => clientOnlyFilters(filters, plan), [filters, plan]);
  const loadedRows = useMemo(
    () => (clientFiltering ? applyClientFilters(unfilteredRows, clientFilters) : unfilteredRows),
    [clientFiltering, unfilteredRows, clientFilters],
  );

  const serverTotal =
    def.source === "whole" ? (firstData ? (mappedByPage.get(0)?.length ?? 0) : null) : total0;
  const total = clientFiltering ? (firstData ? loadedRows.length : null) : serverTotal;
  const pageCount = serverTotal === null ? null : Math.max(1, Math.ceil(serverTotal / pageSize));

  const getRow = useCallback(
    (index: number): GridRow | undefined => {
      if (def.source === "whole" || clientFiltering) return loadedRows[index];
      const page = Math.floor(index / pageSize);
      const row = mappedByPage.get(page)?.[index - page * pageSize];
      if (row && overlay.size > 0) return applyOverlay(row);
      return row;
    },
    [def.source, clientFiltering, loadedRows, mappedByPage, overlay, pageSize, applyOverlay],
  );

  const requestPages = useCallback(
    (start: number, end: number) => {
      if (def.source === "whole") return;
      const first = Math.max(0, Math.floor(start / pageSize));
      const lastWanted = Math.floor(Math.max(start, end) / pageSize) + 1; // +1 = prefetch the next page
      const limit = pageCount === null ? lastWanted : Math.min(lastWanted, pageCount - 1);
      setWantedState((prev) => {
        const base = prev.key === keyString ? prev.pages : [0];
        const next = new Set(base);
        for (let p = first; p <= limit; p += 1) next.add(p);
        if (next.size === base.length) return prev.key === keyString ? prev : { key: keyString, pages: base };
        return { key: keyString, pages: [...next].sort((a, b) => a - b) };
      });
    },
    [def.source, keyString, pageCount, pageSize],
  );
  // Filtered indices are not page indices: while client filters are active the hook pulls pages itself.
  const ensureRange = useCallback(
    (start: number, end: number) => {
      if (!clientFiltering) requestPages(start, end);
    },
    [clientFiltering, requestPages],
  );
  useEffect(() => {
    if (clientFiltering) requestPages(0, (FILTER_AUTOLOAD_PAGES - 1) * pageSize);
  }, [clientFiltering, requestPages, pageSize]);

  const lastData = pageData.filter((d): d is RawPage => !!d).at(-1);
  const canLoadMore =
    def.source === "paged" &&
    (pageCount !== null ? mappedByPage.size < pageCount : lastData?.hasMore === true);
  const highestLoaded = mappedByPage.size > 0 ? Math.max(...mappedByPage.keys()) : -1;
  const loadMore = useCallback(() => {
    if (def.source === "whole") return;
    requestPages((highestLoaded + 1) * pageSize, (highestLoaded + 1) * pageSize);
  }, [def.source, requestPages, highestLoaded, pageSize]);

  const patchRows = useCallback((keys: string[], patch: (row: GridRow) => GridRow) => {
    const keySet = new Set(keys);
    setOverlay((prev) => {
      const next = new Map(prev);
      for (const key of keySet) {
        const before = prev.get(key);
        next.set(key, (row) => patch(before ? before(row) : row));
      }
      return next;
    });
    return () =>
      setOverlay((prev) => {
        const next = new Map(prev);
        for (const key of keySet) next.delete(key);
        return next;
      });
  }, []);

  useEffect(() => {
    if (passive) return;
    const types = new Set<string>();
    const tags = new Set<string>();
    for (const row of unfilteredRows) {
      if (row.artifactType) types.add(row.artifactType);
      for (const tag of row.tags) tags.add(tag);
    }
    setOptions([...types].sort().slice(0, 200), [...tags].sort().slice(0, 200));
  }, [unfilteredRows, setOptions, passive]);

  const categoryId = query.ref.id === "artifacts" && !query.ref.kind ? query.ref.category : undefined;
  const categoryKinds = firstData?.kinds?.length ?? null;
  const category = useMemo(
    () =>
      categoryId
        ? {
            id: categoryId,
            label: isArtifactCategoryId(categoryId) ? categoryInfo(categoryId).label : categoryId,
            kindCount: categoryKinds,
          }
        : null,
    [categoryId, categoryKinds],
  );

  const truncatedFlag = pageData.some((d) => d?.truncated === true);
  const capped = clientFiltering && def.source === "paged" && canLoadMore;
  const filtering = hasActiveFilters(filters);
  useEffect(() => {
    if (passive) return;
    if (!filtering) {
      setReport(null);
      return;
    }
    setReport({
      serverLabels: plan.serverLabels,
      clientLabels: plan.clientLabels,
      loaded: unfilteredRows.length,
      shown: loadedRows.length,
      serverTotal,
      capped,
      truncated: truncatedFlag,
      ...(category ? { scope: categoryScopeText(category) } : {}),
    });
  }, [
    category,
    filtering,
    plan,
    unfilteredRows.length,
    loadedRows.length,
    serverTotal,
    capped,
    truncatedFlag,
    setReport,
    passive,
  ]);

  const firstError = results.find((r) => r.error)?.error ?? null;

  return {
    def,
    pageSize,
    total,
    pageCount,
    pagesLoaded: mappedByPage.size,
    loadedCount: unfilteredRows.length,
    getRow,
    loadedRows,
    ensureRange,
    loadMore,
    isLoading: results[0]?.isLoading ?? false,
    isFetching: results.some((r) => r.isFetching),
    error: firstError instanceof Error ? firstError : firstError ? new Error(String(firstError)) : null,
    refetch: () => {
      setOverlay(new Map());
      for (const r of results) void r.refetch();
    },
    backend: firstData?.backend ?? "",
    truncated: truncatedFlag,
    elapsedMs: firstData?.elapsedMs ?? 0,
    textFilterIsClientSide: true,
    canLoadMore,
    scanned: lastData?.scanned,
    patchRows,
    category,
  };
}
