import { useQueries, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError } from "../../api/client";
import type { RawPage } from "../../api/collections";
import type { TreeNode } from "../../api/runs";
import {
  type CollectionQuery,
  type GridRow,
  type ReviewStatus,
  recordFieldsKey,
  type ServerSortState,
} from "../../contracts/collection";
import { useTimezone } from "../../state/hooks";
import { applyColumnFilters } from "../filters/columnFilters";
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
import { promotedColumn } from "./columns/fieldColumns";
import { serverPathFilter } from "./gridUtils";
import { overlayReview, useReviewMap } from "./reviewMap";
import type { CollectionDef, ColumnSpec } from "./types";

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
  /**
   * Server-known artifact types (exact `artifact_type` values from `/tree`
   * artifact_type_counts) offered by the 유형 menu besides the loaded rows' types. The
   * server's `artifact_type=` match is exact (case-sensitive), so options are never re-cased.
   */
  typeOptions?: readonly string[];
  /**
   * Prefetch the page after the requested ones (default true: grid scrolling). The map's
   * coordinate table turns it off so "500건 더 불러오기" asks for exactly one page.
   */
  prefetchNext?: boolean;
}

const NO_TYPES: readonly string[] = [];

/** Exact artifact types of the run tree's artifact kind nodes (one kind when `kind` is set). */
export function artifactTypesOfTree(nodes: readonly TreeNode[] | undefined, kind?: string): string[] {
  const found = new Set<string>();
  const visit = (list: readonly TreeNode[] | undefined) => {
    for (const node of list ?? []) {
      if (node.collection === "artifacts" && node.kind && (!kind || node.kind === kind)) {
        for (const type of Object.keys(node.artifact_type_counts ?? {})) if (type) found.add(type);
        if (node.artifact_type) found.add(node.artifact_type);
      }
      visit(node.children);
    }
  };
  visit(nodes);
  return [...found].sort();
}

export interface CollectionQueryResult {
  def: CollectionDef;
  /** The query the pages are fetched with (filters folded in: conditions, server text …). */
  query: CollectionQuery;
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
  /** Server sort state of page 0 (artifacts of one kind with `query.sort`); null when not server-sorted. */
  sortState: ServerSortState | null;
  /** Page-level facts of page 0 (files: `ntfs_join`). */
  pageMeta: Record<string, unknown> | undefined;
  /** Column header filters applied to loaded rows only (status line "열 필터: n건 / 불러온 m행 기준"). */
  clientColumnFilters: boolean;
  /** Column header filters the API applied (경로 / 유형 / 확장자 columns). */
  serverColumnFilters: boolean;
  /**
   * Server-filtered match count (`matched`): a number once the server scanned to the end,
   * null while unknown (more pages / scan cap), undefined when the server did not filter.
   */
  serverMatched: number | null | undefined;
}

/** Grid column by id for column filters: the collection's columns, else a promoted `f:<key>` column. */
export function columnResolver(
  def: CollectionDef,
  ref: CollectionQuery["ref"],
  types?: readonly string[],
): (col: string) => ColumnSpec | undefined {
  const columns = def.columnsFor?.(ref, types) ?? def.columns;
  const byId = new Map(columns.map((c) => [c.id, c]));
  return (col) =>
    byId.get(col) ?? (col.startsWith("f:") && col.length > 2 ? promotedColumn(col.slice(2)) : undefined);
}

/** Re-request interval while the server builds a sort index (plan artifact-columns §4.2). */
export const SORT_POLL_MS = 1000;

/** The sort the server applies: artifacts of exactly one kind, or one analysis job's rows. */
export function serverSortOf(query: CollectionQuery): CollectionQuery["sort"] {
  if (!query.sort) return undefined;
  if (query.ref.id === "artifacts" && query.ref.kind) return query.sort;
  if (query.ref.id === "analysis" && query.ref.analysisId) return query.sort;
  return undefined;
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
  const rows = page.rows.map((raw, i) => def.mapRow(raw, page.offset + i, { ref, page }));
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
    (query.ref.id === "artifacts" && !query.ref.kind) || query.ref.id === "files" || query.ref.id === "docs"
      ? (query.ref.category ?? "")
      : "",
    // The search collection pages on the server: its spec is part of every page's key.
    def.source === "whole" || query.ref.id === "search" ? (query.search ?? null) : null,
    def.source === "whole" || query.ref.id === "search" ? (query.extension ?? null) : null,
    query.ref.id === "analysis" ? (query.ref.analysisId ?? "") : "",
    // 파일 시스템 탐색기 folder / special node (files only): another folder is another listing.
    query.ref.id === "files" && (query.ref.dir !== undefined || query.ref.special)
      ? `${query.ref.dir ?? ""}|${query.ref.recursive ? "r" : "d"}|${query.ref.special ?? ""}`
      : "",
    query.ref.id === "artifacts" || query.ref.id === "analysis"
      ? query.pathContains?.trim() || serverPathFilter(query.text) || ""
      : "",
    query.ref.id === "artifacts" ? (query.artifactTypes ?? []).join(",") : "",
    serverSortOf(query) ? `${query.sort?.key}:${query.sort?.order}` : "",
    pageSize,
    // 특이사항 server filters (viewer-families §3.1); empty for every other listing.
    query.flags?.length || query.flagGrade ? `${query.flagGrade ?? ""}|${(query.flags ?? []).join(",")}` : "",
    // Exact record-field filters (`browser=` / `service=`), artifacts only.
    query.ref.id === "artifacts" ? recordFieldsKey(query.fields) : "",
    // Event-log channel / channel-group server filters (R3 O2), artifacts only: two 채널별 nodes
    // of the same kind must not share a cache entry.
    query.ref.id === "artifacts" && (query.channels?.length || query.channelGroups?.length)
      ? `${[...(query.channels ?? [])].sort().join("|")}#${[...(query.channelGroups ?? [])].sort().join("|")}`
      : "",
    // Analysis rows `details` server filters (R3 §3.3).
    query.ref.id === "analysis" && query.detailFilters ? JSON.stringify(query.detailFilters) : "",
    // Row conditions (r4 §2.3: time, 요일·시간대, 부분 결과, 콘텐츠 유형, 위치), artifacts · files · timeline.
    query.rowConditions ? JSON.stringify(query.rowConditions) : "",
    // Timeline server search (`q=`) and display grouping (`group=1`, on unless false).
    query.ref.id === "timeline"
      ? `${query.text?.trim() ?? ""}|${query.group === true ? "group" : "flat"}`
      : "",
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
  "analysis",
]);

/** Pages auto-loaded while client-side filters are active (they only see loaded rows). */
export const FILTER_AUTOLOAD_PAGES = 8;

export function useCollectionQuery(
  rawQuery: CollectionQuery,
  options: CollectionQueryOptions = {},
): CollectionQueryResult {
  const storeFilters = useFilterStore((s) => s.filters);
  const passive = options.passive === true;
  const prefetchNext = options.prefetchNext !== false;
  const filters = passive ? EMPTY_FILTERS : storeFilters;
  const setReport = useFilterStore((s) => s.setReport);
  // Timestamp cells format in the display timezone (re-render rows when it changes); the 요일·시간대
  // conditions are evaluated in it too (server `tz=` and the client predicate).
  const { timezone } = useTimezone();
  const setOptions = useFilterStore((s) => s.setOptions);
  // The run's known artifact types (`/tree`): a 유형 column text selects those containing it.
  const serverTypes = options.typeOptions ?? NO_TYPES;
  // Server-capable filters (path_contains, kind=, extension) fold into the query; the rest stay client-side.
  // biome-ignore lint/correctness/useExhaustiveDependencies: rawQuery fields are listed individually
  const query = useMemo(
    () => applyFiltersToQuery(rawQuery, filters, serverTypes, timezone),
    [
      rawQuery.ref.id,
      rawQuery.ref.kind,
      rawQuery.ref.status,
      rawQuery.ref.category,
      rawQuery.ref.analysisId,
      // 파일 시스템 탐색기 folder / subtree / special node (files): another listing.
      rawQuery.ref.dir,
      rawQuery.ref.recursive,
      rawQuery.ref.special,
      rawQuery.text,
      rawQuery.search,
      rawQuery.extension,
      rawQuery.limit,
      rawQuery.offset,
      rawQuery.sort?.key,
      rawQuery.sort?.order,
      rawQuery.rowConditions,
      rawQuery.group,
      filters,
      serverTypes,
      timezone,
    ],
  );
  const plan = useMemo(
    () => partitionFilters(rawQuery.ref, filters, serverTypes, timezone),
    [rawQuery.ref, filters, serverTypes, timezone],
  );
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
  const page0 = queryClient.getQueryData<RawPage>([...baseKey, "page", 0]);
  // While the server builds a sort index, page 0 is polled and no later page is requested.
  const gateTotal = page0?.sort?.status === "building" ? null : (page0?.total ?? null);
  const sortBuilding = page0?.sort?.status === "building";

  const results = useQueries({
    queries: firstPass.map((p) => ({
      queryKey: [...baseKey, "page", p] as const,
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        def.fetch(runId as string, { ...query, offset: p * pageSize, limit: pageSize }, signal),
      enabled:
        runId !== null &&
        (p === 0 ||
          (!sortBuilding &&
            (gateTotal !== null
              ? p * pageSize < gateTotal
              : queryClient.getQueryData<RawPage>([...baseKey, "page", p - 1])?.hasMore === true))),
      staleTime: 30_000,
      refetchInterval: (q: { state: { data?: RawPage } }) =>
        q.state.data?.sort?.status === "building" ? SORT_POLL_MS : false,
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
  const resolveColumn = useMemo(
    () => columnResolver(def, rawQuery.ref, rawQuery.artifactTypes),
    [def, rawQuery.ref, rawQuery.artifactTypes],
  );
  const loadedRows = useMemo(() => {
    if (!clientFiltering) return unfilteredRows;
    const rows = applyClientFilters(unfilteredRows, clientFilters, timezone);
    return clientFilters.columns.length
      ? applyColumnFilters(rows, clientFilters.columns, resolveColumn)
      : rows;
  }, [clientFiltering, unfilteredRows, clientFilters, resolveColumn, timezone]);

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
      // +1 = prefetch the next page (unless the caller pages one page per request).
      const lastWanted = Math.floor(Math.max(start, end) / pageSize) + (prefetchNext ? 1 : 0);
      const limit = pageCount === null ? lastWanted : Math.min(lastWanted, pageCount - 1);
      setWantedState((prev) => {
        const base = prev.key === keyString ? prev.pages : [0];
        const next = new Set(base);
        for (let p = first; p <= limit; p += 1) next.add(p);
        if (next.size === base.length) return prev.key === keyString ? prev : { key: keyString, pages: base };
        return { key: keyString, pages: [...next].sort((a, b) => a - b) };
      });
    },
    [def.source, keyString, pageCount, pageSize, prefetchNext],
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
    // Server-known types first: a 유형 filter narrows the loaded rows to the picked types,
    // and the menu must still offer the others.
    const types = new Set<string>(serverTypes);
    const tags = new Set<string>();
    const counts: Record<string, number> = {};
    for (const row of unfilteredRows) {
      if (row.artifactType) {
        types.add(row.artifactType);
        counts[row.artifactType] = (counts[row.artifactType] ?? 0) + 1;
      }
      for (const tag of row.tags) tags.add(tag);
    }
    setOptions([...types].sort().slice(0, 200), [...tags].sort().slice(0, 200), counts);
  }, [unfilteredRows, serverTypes, setOptions, passive]);

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
  // `matched` of the latest loaded page (cross-kind / filtered pages report it; the count is
  // final only once a page reached the end).
  const metaMatched = [...pageData].reverse().find((d) => d?.meta && "matched" in d.meta)?.meta?.matched;
  const serverMatched: number | null | undefined =
    metaMatched === undefined
      ? plan.serverLabels.length && firstData
        ? (serverTotal ?? null)
        : undefined
      : typeof metaMatched === "number"
        ? metaMatched
        : null;
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
      ...(serverMatched !== undefined ? { matched: serverMatched } : {}),
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
    serverMatched,
    setReport,
    passive,
  ]);

  const firstError = results.find((r) => r.error)?.error ?? null;

  return {
    def,
    query,
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
    sortState: serverSortOf(query) ? (firstData?.sort ?? null) : null,
    pageMeta: firstData?.meta,
    clientColumnFilters: plan.clientColumns.length > 0,
    serverColumnFilters: plan.serverColumns.length > 0,
    serverMatched,
  };
}
