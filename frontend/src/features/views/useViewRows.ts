/**
 * Rows for the explorer views: the same collection query (and cache entry)
 * as the DataGrid, narrowed by a view predicate and the S8 filter bar.
 */

import { type RefObject, useEffect, useMemo, useState } from "react";
import type { GridRow } from "../../contracts/collection";
import { rowMatchesFilters } from "../filters/filterModel";
import { useFilterStore } from "../filters/filterStore";
import { useRoute } from "../grid/adapter";
import { matchesFilter } from "../grid/gridUtils";
import { type CollectionQueryResult, PAGE_SIZE, useCollectionQuery } from "../grid/useCollectionQuery";

export interface ViewRowsOptions {
  /** Keep only rows the view can draw (images, message rows…); must be a stable function. */
  predicate: (row: GridRow) => boolean;
  /** Apply the grid's text filter `q` (server path filter + client text match). Chat only highlights. */
  textFilter: boolean;
}

export interface ViewRows {
  cq: CollectionQueryResult;
  rows: GridRow[];
  runId: string | null;
  q: string;
}

export function useViewRows({ predicate, textFilter }: ViewRowsOptions): ViewRows {
  const route = useRoute();
  const q = route.q;
  const isSearch = route.collection.id === "search";
  const cq = useCollectionQuery(
    {
      ref: route.collection,
      offset: 0,
      limit: PAGE_SIZE,
      text: textFilter && q ? q : undefined,
      search: route.search,
    },
    { runId: route.runId },
  );
  const filters = useFilterStore((s) => s.filters);
  const rows = useMemo(
    () =>
      cq.loadedRows.filter(
        (row) =>
          predicate(row) &&
          rowMatchesFilters(row, filters) &&
          (!textFilter || isSearch || matchesFilter(row, q)),
      ),
    [cq.loadedRows, predicate, filters, textFilter, isSearch, q],
  );
  return { cq, rows, runId: route.runId, q };
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
