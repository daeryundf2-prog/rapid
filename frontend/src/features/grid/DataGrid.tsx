// biome-ignore-all lint/a11y/useSemanticElements: virtualized ARIA grid; rows are positioned divs, not a <table>
// biome-ignore-all lint/a11y/useFocusableInteractive: roving tabindex; only the focused row is focusable by design

import { useQuery } from "@tanstack/react-query";
import {
  getCoreRowModel,
  getSortedRowModel,
  type LegacyColumnDef,
  useLegacyTable,
} from "@tanstack/react-table/legacy";
import { defaultRangeExtractor, type Range, useVirtualizer } from "@tanstack/react-virtual";
import {
  memo,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import { announce } from "../../a11y";
import { DisabledReason } from "../../a11y/primitives";
import { ApiError, downloadFile } from "../../api/client";
import type { RunExtractResult } from "../../api/extract";
import { getRunTree } from "../../api/runs";
import type { CollectionRef, GridRow } from "../../contracts/collection";
import type { CommandContext } from "../../contracts/command";
import { setColumnFilter } from "../filters/columnFilters";
import { useFilterStore } from "../filters/filterStore";
import { useDensity, useGridLocalStore, useRoute, useSelection, useToast, useViewerTarget } from "./adapter";
import { BatchBar } from "./BatchBar";
import { ColumnFilterRow } from "./ColumnFilterRow";
import { collectionDef, presetColumnIds } from "./columns";
import { isRecord } from "./columns/common";
import {
  colsToKeys,
  effectiveFieldCols,
  fieldColumnId,
  listKeysIn,
  promotedColumn,
  readStoredFieldColumns,
  toggleFieldCol,
  writeStoredFieldColumns,
} from "./columns/fieldColumns";
import { ntfsJoinOf } from "./columns/files";
import { EmptyHintLink } from "./EmptyHintLink";
import { GridFooter, GridToolbar } from "./GridToolbar";
import { buildViewerTarget, type GridCommandHost, runBatch, runNote, useGridCommands } from "./gridCommands";
import {
  compareValues,
  displayText,
  formatCount,
  indexFromRef,
  matchesFilter,
  resultSentence,
  serverPathFilter,
} from "./gridUtils";
import { RowMenu } from "./RowMenu";
import { type CellValue, type ColumnSpec, DENSITY_ROW_HEIGHT, type GridPreset } from "./types";
import {
  artifactTypesOfTree,
  categoryScopeText,
  PAGE_SIZE,
  SORT_POLL_MS,
  useCollectionQuery,
} from "./useCollectionQuery";
import "./grid.css";

interface RowValueReader {
  getValue: (id: string) => unknown;
}
type SortingState = { id: string; desc: boolean }[];
type VisibilityState = Record<string, boolean>;
type ColumnSizingState = Record<string, number>;

const SELECT_COL_WIDTH = 60;
const EMPTY_ROWS: GridRow[] = [];
const PRESETS: readonly GridPreset[] = ["analysis", "compact", "source", "axiom"];
/** AXIOM preset (X13): the tag/status chip column is pinned right after the select cell. */
const AXIOM_PINNED = "tagstatus";

/** Header-sort reasons on the artifacts grid (server sort only; no silent "loaded rows only" sort). */
export const SORT_COLUMN_REASON = "이 열은 전체 정렬을 지원하지 않습니다";
export const SORT_KIND_REASON = "유형을 하나 선택하면 전체 정렬할 수 있습니다";
export const SORT_ANALYSIS_REASON = "분석 결과를 선택하면 전체 정렬할 수 있습니다";
/** A sorted deep link re-asks for the row's position while the index builds (1 s apart). */
export const LOCATE_MAX_TRIES = 60;

export interface DataGridProps {
  /** Overrides the route's run id (tests, embedding). */
  runId?: string | null;
  /** Overrides the route's collection. */
  collection?: CollectionRef;
  /** Initial column preset. */
  initialPreset?: GridPreset;
}

type Anchor = { x: number; y: number } | null;

function readPreset(fallback: GridPreset): GridPreset {
  try {
    const stored = window.localStorage.getItem("rapidtriage.grid.preset");
    if (stored && (PRESETS as readonly string[]).includes(stored)) return stored as GridPreset;
  } catch {
    // Storage may be unavailable; the default preset applies.
  }
  return fallback;
}

function visibilityFor(columns: ColumnSpec[], preset: GridPreset): VisibilityState {
  const visible = new Set(presetColumnIds(columns, preset));
  const first = columns[0]?.id;
  return Object.fromEntries(columns.map((c) => [c.id, c.id === first || visible.has(c.id)]));
}

interface RowViewProps {
  row: GridRow | undefined;
  index: number;
  top: number;
  height: number;
  selected: boolean;
  focused: boolean;
  specs: ColumnSpec[];
  widths: number[];
  /** Sticky `left` offset per visible column (undefined = scrolls). */
  lefts: (number | undefined)[];
  onMenuButton: (index: number, target: HTMLElement) => void;
  /** The row menu is open for this row (trigger aria-expanded). */
  menuOpen: boolean;
  /** Id of the row menu element (trigger aria-controls). */
  menuId: string;
  onToggle: (index: number, checked: boolean) => void;
  /** aria-rowindex of data row 0 (2, or 3 under the column filter row). */
  ariaRowOffset: number;
}

const RowView = memo(function RowView(props: RowViewProps) {
  const { row, index, top, height, selected, focused, specs, widths, lefts } = props;
  const style = { transform: `translateY(${top}px)`, height };
  if (!row) {
    return (
      <div
        role="row"
        aria-rowindex={index + props.ariaRowOffset}
        aria-busy="true"
        className="grid-row grid-row-loading"
        style={style}
      >
        <div role="gridcell" className="grid-cell grid-cell-select" style={{ width: SELECT_COL_WIDTH }} />
        {specs.map((spec, i) => (
          <div
            key={spec.id}
            role="gridcell"
            className={`grid-cell${lefts[i] !== undefined ? " grid-cell-first" : ""}`}
            style={{ width: widths[i], left: lefts[i] }}
          >
            <span className="grid-skeleton" aria-hidden="true" />
          </div>
        ))}
      </div>
    );
  }
  return (
    <div
      role="row"
      aria-rowindex={index + props.ariaRowOffset}
      aria-selected={selected}
      tabIndex={focused ? 0 : -1}
      data-index={index}
      data-row-key={row.rowKey}
      className={`grid-row${selected ? " is-selected" : ""}${focused ? " is-focused" : ""}`}
      style={style}
    >
      <div role="gridcell" className="grid-cell grid-cell-select" style={{ width: SELECT_COL_WIDTH }}>
        <input
          type="checkbox"
          tabIndex={-1}
          aria-label={`${row.title || "행"} 선택`}
          checked={selected}
          onChange={(event) => props.onToggle(index, event.target.checked)}
          onClick={(event) => event.stopPropagation()}
        />
        <button
          type="button"
          tabIndex={-1}
          className="grid-rowmenu-btn"
          aria-label="행 메뉴"
          aria-haspopup="menu"
          aria-expanded={props.menuOpen}
          aria-controls={props.menuOpen ? props.menuId : undefined}
          onClick={(event) => {
            event.stopPropagation();
            props.onMenuButton(index, event.currentTarget);
          }}
        >
          ⋯
        </button>
      </div>
      {specs.map((spec, i) => {
        const text = displayText(spec, row);
        return (
          <div
            key={spec.id}
            role="gridcell"
            data-col={spec.id}
            className={`grid-cell${lefts[i] !== undefined ? " grid-cell-first" : ""}${spec.mono ? " is-mono" : ""}${spec.align === "right" ? " is-right" : ""}`}
            style={{ width: widths[i], left: lefts[i] }}
            title={spec.tooltip ? spec.tooltip(row) : text}
          >
            {spec.render ? spec.render(row) : text}
          </div>
        );
      })}
    </div>
  );
});

export function DataGrid(props: DataGridProps = {}) {
  const route = useRoute();
  const runId = props.runId !== undefined ? props.runId : route.runId;
  const ref = props.collection ?? route.collection;
  const def = collectionDef(ref.id);
  const columnKey = `${ref.id}:${ref.kind ?? ""}`;
  // biome-ignore lint/correctness/useExhaustiveDependencies: columns only depend on the collection/kind
  const baseColumns = useMemo(() => def.columnsFor?.(ref) ?? def.columns, [def, columnKey]);
  // Artifacts (and analysis job rows) are sorted by the server (whole kind / whole job), never
  // client-side over the loaded pages.
  const isAnalysis = ref.id === "analysis";
  const serverSorted = ref.id === "artifacts" || isAnalysis;
  /** The kind whose columns / sort / promoted fields apply; for analysis only once a job is selected. */
  const artifactKind =
    ref.id === "artifacts" ? ref.kind : isAnalysis && ref.analysisId ? ref.kind : undefined;
  /** Promoted-column storage scope ("analysis:<kind>" keeps analysis kinds apart from artifact kinds). */
  const fieldScope = artifactKind ? (isAnalysis ? `analysis:${artifactKind}` : artifactKind) : undefined;
  /** RowRef.kind of this grid's rows: the artifact kind, or the analysis job id. */
  const rowKindOfGrid = isAnalysis ? ref.analysisId : ref.kind;
  const routeSort = artifactKind ? route.sort : undefined;
  // Promoted record-field columns (URL `cols=`, else the kind's stored set); kept across presets.
  const promotedCols = useMemo(() => effectiveFieldCols(route.cols, fieldScope), [route.cols, fieldScope]);
  const promotedKeys = useMemo(() => colsToKeys(promotedCols), [promotedCols]);
  const q = route.q;
  // Shared with the tree (same query key): the run's artifact types (exact server values) for the
  // 유형 menu and the 유형(정확히) suggestions — loaded rows alone shrink once a 유형 filter applies.
  const runTree = useQuery({
    queryKey: ["run-tree", runId],
    queryFn: () => getRunTree(runId as string),
    enabled: Boolean(runId) && ref.id === "artifacts",
    retry: false,
    staleTime: 30_000,
  });
  const treeTypes = useMemo(
    () => (ref.id === "artifacts" ? artifactTypesOfTree(runTree.data?.nodes, ref.kind) : []),
    [ref.id, ref.kind, runTree.data],
  );
  const cq = useCollectionQuery(
    { ref, offset: 0, limit: PAGE_SIZE, text: q || undefined, search: route.search, sort: routeSort },
    { runId, typeOptions: treeTypes },
  );
  // Promoted keys holding lists in the loaded rows: shown, but not server-sortable.
  const listSig = useMemo(
    () => [...listKeysIn(cq.loadedRows, promotedKeys)].sort().join(","),
    [cq.loadedRows, promotedKeys],
  );
  // Columns with several candidate keys sort on the first candidate present in the loaded rows
  // (the one the cells show first), e.g. eventlog 메시지: message, else event_message.
  const candidateSig = useMemo(() => {
    const picked: Record<string, string> = {};
    for (const column of baseColumns) {
      if (!column.sortCandidates) continue;
      const key = column.sortCandidates.find((k) =>
        cq.loadedRows.some((row) => {
          const details = row.fields.details;
          return isRecord(details) && details[k] !== undefined && details[k] !== null && details[k] !== "";
        }),
      );
      if (key) picked[column.id] = key;
    }
    return JSON.stringify(picked);
  }, [baseColumns, cq.loadedRows]);
  const columns = useMemo(() => {
    const picked = JSON.parse(candidateSig) as Record<string, string>;
    const resolved = baseColumns.map((column) => {
      const key = picked[column.id];
      if (!key) return column;
      return { ...column, sortKey: `details.${key}`, sortHint: column.sortHintFor?.(key) ?? column.sortHint };
    });
    if (promotedKeys.length === 0) return resolved;
    const lists = new Set(listSig ? listSig.split(",") : []);
    const takenHeaders = new Set(baseColumns.map((c) => c.header));
    return [
      ...resolved,
      ...promotedKeys.map((key) => promotedColumn(key, { list: lists.has(key), takenHeaders })),
    ];
  }, [baseColumns, candidateSig, promotedKeys, listSig]);
  const { density, setDensity } = useDensity();
  const rowHeight = DENSITY_ROW_HEIGHT[density];
  const selection = useSelection();
  const viewer = useViewerTarget();
  const toast = useToast();

  const [preset, setPreset] = useState<GridPreset>(() => readPreset(props.initialPreset ?? "analysis"));
  const [visibility, setVisibility] = useState<VisibilityState>(() => visibilityFor(baseColumns, preset));
  const [sorting, setSorting] = useState<SortingState>([]);
  const columnFilters = useFilterStore((s) => s.filters.columns);
  const storeTypes = useFilterStore((s) => s.filters.types);
  const storePath = useFilterStore((s) => s.filters.path);
  const patchFilters = useFilterStore((s) => s.patchFilters);
  const [filterRowOpen, setFilterRowOpen] = useState(() => (columnFilters?.length ?? 0) > 0);
  const filterRowShown = filterRowOpen && ref.id !== "intake";
  const onColumnFilter = useCallback(
    (col: string, op: "<" | ">" | ":", value: string) => {
      const current = useFilterStore.getState().filters.columns ?? [];
      patchFilters({ columns: setColumnFilter(current, col, op, value) });
    },
    [patchFilters],
  );
  const [columnSizing, setColumnSizing] = useState<ColumnSizingState>({});
  const [focusIdx, setFocusIdx] = useState(0);
  const [menuAnchor, setMenuAnchor] = useState<Anchor>(null);
  /** Row index whose menu is open (trigger aria-expanded / aria-controls). */
  const [menuRow, setMenuRow] = useState<number | null>(null);
  const menuId = useId();
  const [tagPromptOpen, setTagPromptOpen] = useState(false);
  const [extractResult, setExtractResult] = useState<RunExtractResult | null>(null);
  /** Last server-sort refusal ("unsupported"), shown in the sort status line until the next sort. */
  const [sortNotice, setSortNotice] = useState<string | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  /** Ids of the hidden sort-key hints ("실행 파일 정렬 (executable_hint 기준)"), referenced by aria-describedby. */
  const hintPrefix = useId();
  const filterRef = useRef<HTMLInputElement>(null);
  const anchorRef = useRef<number | null>(null);
  const wantDomFocus = useRef(false);
  const userNavigated = useRef(false);
  const restoredRow = useRef(false);

  // Preset / collection change resets the column model and view state.
  const collectionKey = `${ref.id}:${ref.kind ?? ""}:${ref.status ?? ""}:${ref.category ?? ""}:${ref.analysisId ?? ""}`;
  // biome-ignore lint/correctness/useExhaustiveDependencies: reset only when the collection or preset changes
  useEffect(() => {
    setVisibility(visibilityFor(columns, preset));
  }, [collectionKey, preset]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: reset only when the collection changes
  useEffect(() => {
    setSorting([]);
    setSortNotice(null);
    setColumnSizing({});
    setFocusIdx(0);
    anchorRef.current = null;
    restoredRow.current = false;
    // Focus is identified by the route's RowRef, never by a stale position: a new collection
    // starts unnavigated, so the automatic first-row focus never rewrites `row=`.
    userNavigated.current = false;
  }, [collectionKey, runId]);
  // Server order / server path filter changed: positions mean other records now. Re-resolve the
  // focused row from the route's `row=` (locate= under a server sort), else fall back to row 0.
  const orderKey = serverSorted
    ? `${routeSort ? `${routeSort.key}:${routeSort.order}` : ""}|${serverPathFilter(q) ?? ""}`
    : "";
  const lastOrderKey = useRef(orderKey);
  useEffect(() => {
    if (lastOrderKey.current === orderKey) return;
    lastOrderKey.current = orderKey;
    userNavigated.current = false;
    restoredRow.current = false;
    anchorRef.current = null;
    setFocusIdx(0);
  }, [orderKey]);

  // A shared link without `cols=` gets the kind's stored promoted columns written into the URL.
  const { setCols, setSort } = route;
  useEffect(() => {
    if (!artifactKind || !fieldScope || isAnalysis || route.cols?.length) return;
    const stored = readStoredFieldColumns(fieldScope);
    // Only for the kind still on screen (a fast kind switch must not carry one kind's columns over).
    if (stored?.length && useGridLocalStore.getState().route.collection.kind === artifactKind)
      setCols(stored);
  }, [artifactKind, fieldScope, isAnalysis, route.cols, setCols]);
  const toggleField = useCallback(
    (key: string, on: boolean) => {
      if (!fieldScope) return;
      const next = toggleFieldCol(promotedCols, key, on);
      writeStoredFieldColumns(fieldScope, next);
      setCols(next);
      // A column hidden earlier through the checkbox list comes back when promoted again.
      if (on) setVisibility((prev) => ({ ...prev, [fieldColumnId(key)]: true }));
    },
    [fieldScope, promotedCols, setCols],
  );

  const needle = q.trim();
  const clientSorting = !serverSorted && sorting.length > 0;
  const compactMode = needle !== "" || clientSorting;

  const filtered = useMemo(
    () => (needle ? cq.loadedRows.filter((row) => matchesFilter(row, needle)) : cq.loadedRows),
    [cq.loadedRows, needle],
  );

  // AXIOM preset: chip column first (pinned after the select cell), then the two-line title.
  const orderedColumns = useMemo(() => {
    if (preset !== "axiom") return columns;
    const pinned = columns.find((c) => c.id === AXIOM_PINNED);
    return pinned ? [pinned, ...columns.filter((c) => c !== pinned)] : columns;
  }, [columns, preset]);

  const tableColumns = useMemo<LegacyColumnDef<GridRow>[]>(
    () =>
      orderedColumns.map((spec) => ({
        id: spec.id,
        header: spec.header,
        accessorFn: (row: GridRow) => spec.value(row),
        size: spec.width,
        minSize: spec.minWidth ?? 60,
        sortingFn: (a: RowValueReader, b: RowValueReader, id: string) =>
          compareValues(a.getValue(id) as CellValue, b.getValue(id) as CellValue),
      })),
    [orderedColumns],
  );

  const table = useLegacyTable<GridRow>({
    data: compactMode ? filtered : EMPTY_ROWS,
    columns: tableColumns,
    state: { sorting, columnVisibility: visibility, columnSizing },
    onSortingChange: setSorting,
    onColumnVisibilityChange: setVisibility,
    onColumnSizingChange: setColumnSizing,
    columnResizeMode: "onChange",
    enableColumnResizing: true,
    getRowId: (row) => row.rowKey,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const visibleColumns = table.getVisibleLeafColumns();
  const specById = useMemo(() => new Map(columns.map((c) => [c.id, c])), [columns]);
  const specs = visibleColumns.map((c) => specById.get(c.id)).filter((c): c is ColumnSpec => !!c);
  const widths = visibleColumns.map((c) => c.getSize());
  // Publish the shown column ids (the meta tab's "기본 열에 이미 표시됩니다" checks them).
  const visibleSig = specs.map((s) => s.id).join("\n");
  useEffect(() => {
    const { setVisibleColumnIds } = useGridLocalStore.getState();
    setVisibleColumnIds(visibleSig ? visibleSig.split("\n") : []);
  }, [visibleSig]);
  useEffect(() => () => useGridLocalStore.getState().setVisibleColumnIds(null), []);
  const totalWidth = SELECT_COL_WIDTH + widths.reduce((sum, w) => sum + w, 0);
  // Sticky columns: the first data column, plus the title after a pinned AXIOM chip column.
  const stickyCount = preset === "axiom" && specs[0]?.id === AXIOM_PINNED && specs.length > 1 ? 2 : 1;
  const lefts: (number | undefined)[] = [];
  let stickyLeft = SELECT_COL_WIDTH;
  widths.forEach((w, i) => {
    lefts.push(i < stickyCount ? stickyLeft : undefined);
    stickyLeft += w;
  });
  const stickyWidth = widths.slice(0, stickyCount).reduce((sum, w) => sum + w, 0);

  const displayRows = compactMode ? table.getRowModel().rows.map((r) => r.original) : EMPTY_ROWS;
  const sortState = cq.sortState;
  const sortBuilding = sortState?.status === "building";
  // While the server builds the sort index there are no rows to show (only the status line).
  const displayCount = sortBuilding ? 0 : compactMode ? displayRows.length : (cq.total ?? cq.loadedCount);
  const getDisplayRow = useCallback(
    (index: number): GridRow | undefined => (compactMode ? displayRows[index] : cq.getRow(index)),
    [compactMode, displayRows, cq.getRow],
  );

  const clampedFocus = displayCount === 0 ? -1 : Math.min(focusIdx, displayCount - 1);
  const focusIdxRef = useRef(clampedFocus);
  focusIdxRef.current = clampedFocus;

  // The extractor identity changes with the focused row so the virtualizer recomputes and keeps it mounted.
  const rangeExtractor = useCallback(
    (range: Range) => {
      const base = defaultRangeExtractor(range);
      if (clampedFocus >= 0 && !base.includes(clampedFocus))
        return [...base, clampedFocus].sort((a, b) => a - b);
      return base;
    },
    [clampedFocus],
  );

  const virtualizer = useVirtualizer({
    count: displayCount,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan: 12,
    rangeExtractor,
    initialRect: { width: 1000, height: 600 },
  });
  const virtualItems = virtualizer.getVirtualItems();
  // `range` excludes the always-rendered focused row, so jumping (End) does not request every page in between.
  const firstVisible = virtualizer.range?.startIndex ?? 0;
  const lastVisible = virtualizer.range?.endIndex ?? 0;

  // Random-access mode: request the server pages the viewport covers (+ prefetch next).
  const { ensureRange, loadMore } = cq;
  useEffect(() => {
    if (!compactMode) ensureRange(firstVisible, lastVisible);
  }, [compactMode, ensureRange, firstVisible, lastVisible]);

  // Compact mode: near the end, after the user scrolled, pull the next page.
  useEffect(() => {
    if (!compactMode) return;
    const scrolled = (scrollRef.current?.scrollTop ?? 0) > 0;
    if (scrolled && lastVisible >= displayCount - 15 && cq.canLoadMore) {
      loadMore();
    }
  }, [compactMode, lastVisible, displayCount, cq.canLoadMore, loadMore]);

  const focusedRow = clampedFocus >= 0 ? getDisplayRow(clampedFocus) : undefined;
  const selectedKeys = selection.selectedKeys;

  // Rows by key for commands (selection may span pages and filters).
  const rowsByKey = useMemo(() => new Map(cq.loadedRows.map((r) => [r.rowKey, r])), [cq.loadedRows]);

  // Focused row -> store and viewer. Identity is published SYNCHRONOUSLY (never debounced) so a
  // mark pressed right after J/K applies to the new row; only the viewer's load may be debounced.
  const { setFocused } = selection;
  const { publish, publishFocusedRow } = viewer;
  const { setRow } = route;
  const lastPublished = useRef<GridRow | null>(null);
  const publishNow = useCallback(
    (row: GridRow) => {
      if (!runId) return;
      lastPublished.current = row;
      publishFocusedRow(row, buildViewerTarget(runId, row));
      setRow(row.ref);
    },
    [runId, publishFocusedRow, setRow],
  );
  useEffect(() => {
    if (!focusedRow || !userNavigated.current || !runId) {
      setFocused(focusedRow?.rowKey ?? null);
      // Automatic focus (first loaded row, deep-link restore): the viewer loads the row too.
      // No setRow here — the shell keeps the URL canonical until the analyst moves/selects.
      if (focusedRow && runId && lastPublished.current !== focusedRow) {
        lastPublished.current = focusedRow;
        publishFocusedRow(focusedRow, buildViewerTarget(runId, focusedRow));
      }
      return;
    }
    if (lastPublished.current !== focusedRow) publishNow(focusedRow);
  }, [focusedRow, runId, setFocused, publishNow, publishFocusedRow]);

  // Server-sorted deep link: the locator is the JSONL record_index, not the display position;
  // ask the server where that record sits in the sorted order (`locate=` → `sort.position`).
  const sortReady = cq.sortState?.status === "ready";
  const serverPath = serverSorted ? serverPathFilter(q) : undefined;
  const locateTarget =
    routeSort && artifactKind && route.rowRef?.collection === ref.id && route.rowRef.kind === rowKindOfGrid
      ? indexFromRef(route.rowRef)
      : null;
  // With a server path filter the sorted position of a record is not a page position: no locate.
  const locateKey =
    locateTarget !== null && routeSort && !serverPath
      ? `${runId}|${rowKindOfGrid}|${routeSort.key}:${routeSort.order}|${locateTarget}`
      : null;
  const [located, setLocated] = useState<{ key: string; position: number | null } | null>(null);
  const locateRow = def.locate;
  // biome-ignore lint/correctness/useExhaustiveDependencies: `ref` is identified by locateKey
  useEffect(() => {
    if (!locateKey || !sortReady || restoredRow.current || !runId || !artifactKind || !routeSort) return;
    if (locateTarget === null || located?.key === locateKey || !locateRow) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const attempt = (n: number) => {
      locateRow(runId, ref, routeSort, locateTarget, controller.signal)
        .then((result) => {
          if (controller.signal.aborted) return;
          // The index may be rebuilding (evicted, restarted server): ask again, bounded.
          if (result.status === "building" && n < LOCATE_MAX_TRIES) {
            timer = setTimeout(() => attempt(n + 1), SORT_POLL_MS);
            return;
          }
          setLocated({ key: locateKey, position: result.position });
        })
        .catch(() => {
          if (!controller.signal.aborted) setLocated({ key: locateKey, position: null });
        });
    };
    attempt(1);
    return () => {
      controller.abort();
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [locateKey, sortReady, runId, artifactKind, routeSort, locateTarget, located, locateRow]);

  // Deep link: restore `row=` (focus + scroll) once, resolving the server page from the locator.
  useEffect(() => {
    const target = route.rowRef;
    if (!target || restoredRow.current || compactMode) return;
    if (routeSort && serverPath) {
      // Sorted + path-filtered: neither the locator nor locate= gives a display position; row 0.
      restoredRow.current = true;
      return;
    }
    let idx: number | null;
    if (locateKey) {
      if (located?.key !== locateKey) return; // waiting for the sorted position
      idx = located.position;
    } else {
      idx = indexFromRef(target);
    }
    if (idx === null) {
      restoredRow.current = true;
      return;
    }
    ensureRange(idx, idx);
    const row = cq.getRow(idx);
    if (row && row.ref.locator !== target.locator) {
      // Path-filtered (unsorted) pages: the locator index is not the display position; leave focus alone.
      restoredRow.current = true;
      return;
    }
    if (row) {
      restoredRow.current = true;
      setFocusIdx(idx);
      virtualizer.scrollToIndex(idx, { align: "center" });
    }
  }, [
    route.rowRef,
    compactMode,
    ensureRange,
    cq.getRow,
    virtualizer,
    locateKey,
    located,
    routeSort,
    serverPath,
  ]);

  // Move DOM focus onto the focused row after keyboard navigation (rows are virtualized).
  const itemSignature = `${firstVisible}-${lastVisible}-${clampedFocus}-${focusedRow ? 1 : 0}`;
  // biome-ignore lint/correctness/useExhaustiveDependencies: runs when the rendered window changes
  useEffect(() => {
    if (!wantDomFocus.current || clampedFocus < 0) return;
    const el = scrollRef.current?.querySelector<HTMLElement>(`[data-index="${clampedFocus}"]`);
    if (el) {
      el.focus({ preventScroll: true });
      wantDomFocus.current = false;
    }
  }, [itemSignature, displayCount]);

  const setSelectionKeys = selection.select;
  const rangeKeys = useCallback(
    (from: number, to: number): string[] => {
      const keys: string[] = [];
      for (let i = Math.min(from, to); i <= Math.max(from, to); i += 1) {
        const row = getDisplayRow(i);
        if (row) keys.push(row.rowKey);
      }
      return keys;
    },
    [getDisplayRow],
  );

  const moveFocus = useCallback(
    (next: number, extend: boolean) => {
      if (displayCount === 0) return;
      const clamped = Math.max(0, Math.min(displayCount - 1, next));
      userNavigated.current = true;
      wantDomFocus.current = true;
      if (extend) {
        const anchor = anchorRef.current ?? focusIdxRef.current;
        anchorRef.current = anchor;
        setSelectionKeys(rangeKeys(anchor, clamped));
      }
      setFocusIdx(clamped);
      const nextRow = getDisplayRow(clamped);
      if (nextRow) publishNow(nextRow);
      if (!compactMode) ensureRange(clamped, clamped);
      virtualizer.scrollToIndex(clamped, { align: "auto" });
    },
    [
      displayCount,
      compactMode,
      ensureRange,
      rangeKeys,
      setSelectionKeys,
      virtualizer,
      getDisplayRow,
      publishNow,
    ],
  );

  const toggleAt = useCallback(
    (index: number, on?: boolean) => {
      const row = getDisplayRow(index);
      if (!row) return;
      const next = new Set(selectedKeys);
      const shouldSelect = on ?? !next.has(row.rowKey);
      if (shouldSelect) next.add(row.rowKey);
      else next.delete(row.rowKey);
      anchorRef.current = index;
      setSelectionKeys([...next]);
    },
    [getDisplayRow, selectedKeys, setSelectionKeys],
  );

  const openRow = useCallback(
    (row: GridRow, mode?: import("../../contracts/viewer").ViewerMode) => {
      if (!runId) return;
      publish(buildViewerTarget(runId, row, mode));
      setRow(row.ref);
      viewer.requestFocus();
    },
    [runId, publish, setRow, viewer],
  );

  const pageRows = Math.max(1, virtualItems.length > 4 ? lastVisible - firstVisible - 12 : 10);

  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    if (target.closest("input, button, select, textarea")) return;
    const rowEl = target.closest<HTMLElement>("[data-index]");
    // Focus on the grid container (or its scroll area) rather than a row: act on the
    // current roving row, so J/K/Enter work right after navigation.
    const onContainer = !rowEl && target.closest('[role="grid"]') !== null;
    if (!rowEl && !onContainer) return;
    const index = rowEl ? Number(rowEl.dataset.index) : Math.max(clampedFocus, 0);
    if (!Number.isFinite(index)) return;
    if (onContainer) wantDomFocus.current = true;
    const mod = event.ctrlKey || event.metaKey;
    const key = event.key;
    const lower = key.length === 1 ? key.toLowerCase() : key;
    const handled = (fn: () => void) => {
      event.preventDefault();
      fn();
    };
    if (key === "ArrowDown" || (lower === "j" && !mod && !event.altKey)) {
      return handled(() => moveFocus(index + 1, event.shiftKey));
    }
    if (key === "ArrowUp" || (lower === "k" && !mod && !event.altKey)) {
      return handled(() => moveFocus(index - 1, event.shiftKey));
    }
    if (key === "Home") return handled(() => moveFocus(0, event.shiftKey));
    if (key === "End") return handled(() => moveFocus(displayCount - 1, event.shiftKey));
    if (key === "PageDown") return handled(() => moveFocus(index + pageRows, event.shiftKey));
    if (key === "PageUp") return handled(() => moveFocus(index - pageRows, event.shiftKey));
    if (key === " " || key === "Spacebar") {
      return handled(() => toggleAt(index));
    }
    if (key === "Enter") {
      const row = getDisplayRow(index);
      if (row) handled(() => openRow(row));
      return;
    }
    if (mod && lower === "a") {
      return handled(() => setSelectionKeys(rangeKeys(0, displayCount - 1)));
    }
    if (key === "Escape" && selectedKeys.size > 0) {
      return handled(() => setSelectionKeys([]));
    }
    if ((key === "F10" && event.shiftKey) || key === "ContextMenu") {
      const rect = target.closest<HTMLElement>("[data-index]")?.getBoundingClientRect();
      return handled(() => {
        setFocusIdx(index);
        setMenuRow(index);
        setMenuAnchor({ x: (rect?.left ?? 0) + SELECT_COL_WIDTH, y: rect?.bottom ?? 0 });
      });
    }
  };

  const onRowMouseDown = (event: ReactMouseEvent<HTMLDivElement>) => {
    const rowEl = (event.target as HTMLElement).closest<HTMLElement>("[data-index]");
    // In-cell links (cross-case 케이스) navigate on their own; they do not select the row.
    if (!rowEl || (event.target as HTMLElement).closest("input, button, a[href]")) return;
    const index = Number(rowEl.dataset.index);
    const row = getDisplayRow(index);
    if (!row || event.button !== 0) return;
    userNavigated.current = true;
    setFocusIdx(index);
    publishNow(row);
    if (event.shiftKey && anchorRef.current !== null) {
      const keys = rangeKeys(anchorRef.current, index);
      setSelectionKeys(event.ctrlKey || event.metaKey ? [...new Set([...selectedKeys, ...keys])] : keys);
    } else if (event.ctrlKey || event.metaKey) {
      toggleAt(index);
    } else {
      anchorRef.current = index;
      setSelectionKeys([row.rowKey]);
    }
  };

  const onContextMenu = (event: ReactMouseEvent<HTMLDivElement>) => {
    const rowEl = (event.target as HTMLElement).closest<HTMLElement>("[data-index]");
    if (!rowEl) return;
    event.preventDefault();
    const index = Number(rowEl.dataset.index);
    const row = getDisplayRow(index);
    if (!row) return;
    userNavigated.current = true;
    setFocusIdx(index);
    if (!selectedKeys.has(row.rowKey)) {
      anchorRef.current = index;
      setSelectionKeys([row.rowKey]);
    }
    setMenuRow(index);
    setMenuAnchor({ x: event.clientX, y: event.clientY });
  };

  const menuOpenRow = useRef<number | null>(null);
  menuOpenRow.current = menuAnchor !== null ? menuRow : null;
  const onMenuButton = useCallback((index: number, target: HTMLElement) => {
    if (menuOpenRow.current === index) {
      // Same trigger again: toggle closed (aria-expanded true → false).
      setMenuAnchor(null);
      setMenuRow(null);
      return;
    }
    setFocusIdx(index);
    setMenuRow(index);
    const rect = target.getBoundingClientRect();
    setMenuAnchor({ x: rect.left, y: rect.bottom });
  }, []);

  const onToggleCheckbox = useCallback(
    (index: number, checked: boolean) => toggleAt(index, checked),
    [toggleAt],
  );

  // `/` focuses the filter (not while typing somewhere else).
  useEffect(() => {
    const onDocKey = (event: KeyboardEvent) => {
      if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey) return;
      const t = event.target as HTMLElement | null;
      if (
        t &&
        (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)
      ) {
        return;
      }
      event.preventDefault();
      filterRef.current?.focus();
      filterRef.current?.select();
    };
    document.addEventListener("keydown", onDocKey);
    return () => document.removeEventListener("keydown", onDocKey);
  }, []);

  const selectedRows = useCallback(
    () => [...selectedKeys].map((key) => rowsByKey.get(key)).filter((r): r is GridRow => !!r),
    [selectedKeys, rowsByKey],
  );

  const host: GridCommandHost = {
    runId,
    collection: ref,
    getFocusedRow: () => focusedRow,
    getSelectedRows: selectedRows,
    openRow,
    setFilter: route.setQuery,
    navigate: route.navigate,
    patchRows: cq.patchRows,
    toast: toast.show,
    refetch: cq.refetch,
    showExtract: setExtractResult,
    openTagPrompt: () => setTagPromptOpen(true),
    runIsActive: false,
  };
  useGridCommands(host);

  const context: CommandContext = {
    runId,
    collection: ref.id,
    selectedRowKeys: [...selectedKeys],
    focusedRowKey: focusedRow?.rowKey ?? null,
    viewerHasTarget: viewer.target !== null,
    runIsActive: false,
  };

  const returnToGrid = useCallback(() => {
    const el = scrollRef.current?.querySelector<HTMLElement>("[data-index][tabindex='0']");
    el?.focus();
  }, []);

  // One polite sentence per result of a query the analyst asked for (collection, filters, sort).
  // Background refetches (job polling, review overlays) that only change the count stay silent,
  // and the elapsed time is not part of the key.
  const resultCount = compactMode ? displayCount : (cq.total ?? displayCount);
  const filterSig = useFilterStore((s) => JSON.stringify(s.filters));
  const querySig = `${runId}|${collectionKey}|${q}|${routeSort ? `${routeSort.key}:${routeSort.order}` : ""}|${filterSig}`;
  const announcedFor = useRef("");
  const elapsedRef = useRef(cq.elapsedMs);
  elapsedRef.current = cq.elapsedMs;
  useEffect(() => {
    if (cq.isLoading || !runId || announcedFor.current === querySig) return;
    announcedFor.current = querySig;
    announce(resultSentence(resultCount, cq.backend, elapsedRef.current));
  }, [cq.isLoading, runId, querySig, resultCount, cq.backend]);

  const lastToast = toast.toasts.at(-1);
  useEffect(() => {
    if (lastToast)
      announce(lastToast.message, { politeness: lastToast.tone === "error" ? "assertive" : "polite" });
  }, [lastToast]);

  const sortOf = (spec: ColumnSpec): "ascending" | "descending" | "none" => {
    if (serverSorted) {
      if (!routeSort || !spec.sortKey || spec.sortKey !== routeSort.key) return "none";
      return routeSort.order === "desc" ? "descending" : "ascending";
    }
    const s = sorting.find((item) => item.id === spec.id);
    return s ? (s.desc ? "descending" : "ascending") : "none";
  };
  const sortReason = (spec: ColumnSpec): string | null => {
    if (!serverSorted) return null;
    if (!artifactKind) return isAnalysis ? SORT_ANALYSIS_REASON : SORT_KIND_REASON;
    return spec.sortKey ? null : (spec.unsortableReason ?? SORT_COLUMN_REASON);
  };
  const cycleSort = (spec: ColumnSpec) => {
    const current = sortOf(spec);
    if (serverSorted) {
      if (sortReason(spec) || !spec.sortKey) return;
      setSortNotice(null);
      setSort(
        current === "none"
          ? { key: spec.sortKey, order: "asc" }
          : current === "ascending"
            ? { key: spec.sortKey, order: "desc" }
            : undefined,
      );
      setFocusIdx(0);
      scrollRef.current?.scrollTo?.({ top: 0 });
      return;
    }
    const id = spec.id;
    setSorting(
      current === "none" ? [{ id, desc: false }] : current === "ascending" ? [{ id, desc: true }] : [],
    );
    setFocusIdx(0);
  };

  // "unsupported": the server cannot sort this key: say why and drop the sort (never a silent page sort).
  useEffect(() => {
    if (sortState?.status !== "unsupported") return;
    setSortNotice(sortState.reason ?? "서버가 이 열의 전체 정렬을 지원하지 않습니다.");
    setSort(undefined);
  }, [sortState, setSort]);

  const sortedSpec = routeSort ? columns.find((c) => c.sortKey === routeSort.key) : undefined;
  // A 409 survived the automatic retry: the server's own words go in the status line.
  const staleDetail =
    serverSorted && cq.error instanceof ApiError && cq.error.status === 409 ? cq.error.message : "";
  const sortStatusText = !serverSorted
    ? ""
    : staleDetail
      ? `정렬 인덱스를 다시 만들어야 합니다: ${staleDetail}`
      : sortNotice
        ? `전체 정렬을 할 수 없습니다: ${sortNotice}`
        : routeSort && sortBuilding
          ? `전체 정렬 인덱스 생성 중 … ${Math.round((sortState?.progress ?? 0) * 100)}%`
          : routeSort && sortState?.status === "ready"
            ? `정렬: ${sortedSpec?.header ?? routeSort.key} ${routeSort.order === "desc" ? "▼" : "▲"} (전체 ${
                cq.total !== null ? formatCount(cq.total) : "-"
              }건)`
            : routeSort
              ? "전체 정렬 준비 중 …"
              : "";
  // The status line is plain text; its transitions go through the one announce() live region.
  const sortAnnouncement = !serverSorted
    ? ""
    : staleDetail
      ? sortStatusText
      : sortNotice
        ? sortStatusText
        : routeSort && sortBuilding
          ? "전체 정렬 인덱스 생성을 시작했습니다."
          : routeSort && sortState?.status === "ready"
            ? sortStatusText
            : "";
  useEffect(() => {
    if (sortAnnouncement) announce(sortAnnouncement);
  }, [sortAnnouncement]);

  // 유형(정확히) suggestions: the run's artifact types (`/tree` artifact_type_counts) + loaded rows.
  const typeSuggestions = useMemo(() => {
    if (ref.id !== "artifacts" || !filterRowShown) return [];
    const found = new Set<string>(treeTypes);
    for (const row of cq.loadedRows) if (row.artifactType) found.add(row.artifactType);
    return [...found].sort();
  }, [ref.id, filterRowShown, treeTypes, cq.loadedRows]);
  /** Header row (+ the column filter row when shown) precede the data rows in aria-rowindex. */
  const headRows = filterRowShown ? 2 : 1;
  const rowCountAria = (compactMode ? displayCount : (cq.total ?? -1)) + headRows;
  // Files NTFS columns: until an NTFS-meta analysis is joined their headers link to running it.
  const ntfsJoin = ref.id === "files" ? ntfsJoinOf(cq.pageMeta) : null;
  const hintsActive = ref.id === "files" && !cq.isLoading && ntfsJoin === null;
  const statusLines: { id: string; text: string }[] = [];
  if (cq.clientColumnFilters) {
    statusLines.push({
      id: "colfilter",
      text: `열 필터: ${formatCount(cq.total ?? 0)}건 / 불러온 ${formatCount(cq.loadedCount)}행 기준`,
    });
  } else if (cq.serverColumnFilters && cq.serverMatched !== undefined) {
    statusLines.push({
      id: "colfilter",
      text:
        cq.serverMatched === null
          ? `열 필터: ${formatCount(cq.loadedCount)}건 이상 (서버 필터, 계속 불러오는 중)`
          : `열 필터: ${formatCount(cq.serverMatched)}건 (서버 필터)`,
    });
  }
  if (ntfsJoin) {
    const analysis = (ntfsJoin.analysis_id ?? "").slice(0, 8);
    statusLines.push({
      id: "ntfs",
      // The join counts the current page only (backend `ntfs_join`): say so. A not-joined
      // status (too_large / no_volume_prefix / skipped) says why instead of "0행 일치".
      text: ntfsJoin.joined
        ? `NTFS 메타: 이 페이지 ${formatCount(ntfsJoin.matched)}/${formatCount(ntfsJoin.total)}행 일치 (분석 ${analysis})`
        : `NTFS 메타: 조인하지 않음 — ${ntfsJoin.reason} (분석 ${analysis})`,
    });
  }
  const currentPage = Math.min(cq.pageCount ?? 1, Math.floor(firstVisible / cq.pageSize) + 1);

  const emptyMessage = !runId
    ? "케이스를 먼저 선택하세요."
    : ref.id === "intake"
      ? "접수 요약은 그리드가 아닌 요약 화면에서 확인합니다."
      : ref.id === "search" && !(route.search && route.search.keywords.length > 0)
        ? "검색어를 입력하면 결과가 여기에 표시됩니다."
        : sortBuilding
          ? "전체 정렬 인덱스를 만드는 중입니다. 끝나면 정렬된 순서로 표시합니다."
          : compactMode
            ? "조건에 맞는 행이 없습니다. 불러온 행 안에서만 필터합니다."
            : "표시할 행이 없습니다.";

  const serverFiltering =
    cq.serverColumnFilters || storeTypes.length > 0 || Boolean(storePath) || Boolean(serverPathFilter(q));
  const loadingMessage = serverFiltering
    ? "서버에서 조건에 맞는 행을 찾는 중입니다 … (큰 유형은 수 초 걸릴 수 있습니다)"
    : "목록을 불러오는 중입니다 …";

  return (
    <section
      className="grid-root"
      aria-label={`${def.label} 그리드`}
      data-density={density}
      data-preset={preset}
    >
      <GridToolbar
        filterRef={filterRef}
        query={q}
        onQuery={route.setQuery}
        onReturnToGrid={returnToGrid}
        preset={preset}
        onPreset={(next) => {
          setPreset(next);
          try {
            window.localStorage.setItem("rapidtriage.grid.preset", next);
          } catch {
            // Preset simply does not persist.
          }
        }}
        density={density}
        onDensity={setDensity}
        columns={columns}
        visibility={visibility}
        onToggleColumn={(id, visible) => setVisibility((prev) => ({ ...prev, [id]: visible }))}
        collectionLabel={def.label}
        columnFilters={
          ref.id === "intake"
            ? undefined
            : {
                open: filterRowShown,
                count: columnFilters?.length ?? 0,
                onToggle: () => setFilterRowOpen((open) => !open),
              }
        }
        fieldPicker={
          artifactKind
            ? {
                rows: cq.loadedRows,
                columns: baseColumns,
                promoted: promotedKeys,
                onToggle: toggleField,
              }
            : undefined
        }
      />
      <BatchBar
        selectedCount={selectedKeys.size}
        context={context}
        onDisabled={(reason) => toast.show(reason, "info")}
        onClear={() => setSelectionKeys([])}
        onTag={(tag) => void runBatch(host, "tag", tag)}
        tagPromptOpen={tagPromptOpen}
        onTagPromptChange={setTagPromptOpen}
        onNote={runId ? (note) => void runNote(host, note) : undefined}
      />

      {serverSorted ? (
        <p className="grid-sortstatus" data-testid="grid-sort-status" hidden={!sortStatusText}>
          {sortStatusText}
        </p>
      ) : null}

      {statusLines.map((line) => (
        <p key={line.id} className="grid-sortstatus" data-testid={`grid-${line.id}-status`}>
          {line.text}
        </p>
      ))}

      {cq.error ? (
        <div className="grid-error" role="alert">
          <span>목록을 불러오지 못했습니다. {cq.error.message}</span>
          <button type="button" className="grid-btn" onClick={cq.refetch}>
            다시 시도
          </button>
        </div>
      ) : null}

      <div
        ref={scrollRef}
        className="grid-scroll"
        role="grid"
        aria-label={`${def.label} 목록`}
        aria-rowcount={rowCountAria}
        aria-colcount={specs.length + 1}
        aria-multiselectable="true"
        aria-busy={cq.isLoading}
        // Keep scrollIntoView / focus reveal clear of the sticky header row and the sticky
        // select + first columns, so nothing scrolled "into view" lands underneath them.
        style={{
          scrollPaddingLeft: SELECT_COL_WIDTH + stickyWidth,
          scrollPaddingTop: rowHeight + (filterRowShown ? rowHeight + 4 : 0),
        }}
        onKeyDown={onKeyDown}
        onMouseDown={onRowMouseDown}
        onContextMenu={onContextMenu}
      >
        <div className="grid-inner" style={{ width: totalWidth }}>
          <div role="rowgroup" className="grid-head">
            <div role="row" aria-rowindex={1} className="grid-row grid-header" style={{ height: rowHeight }}>
              <div
                role="columnheader"
                className="grid-cell grid-cell-select"
                style={{ width: SELECT_COL_WIDTH }}
              >
                <span className="sr-only">선택</span>
              </div>
              {visibleColumns.map((column, i) => {
                const spec = specs[i];
                if (!spec) return null;
                const sort = sortOf(spec);
                const reason = sortReason(spec);
                const hint = hintsActive ? spec.emptyHint : undefined;
                const hintId = `${hintPrefix}-empty-${spec.id}`;
                const describedBy =
                  [spec.sortHint ? `${hintPrefix}-${spec.id}` : "", hint ? hintId : ""]
                    .filter(Boolean)
                    .join(" ") || undefined;
                return (
                  <div
                    key={column.id}
                    role="columnheader"
                    aria-sort={sort}
                    aria-label={hint ? spec.header : undefined}
                    data-col={column.id}
                    className={`grid-cell grid-hcell${lefts[i] !== undefined ? " grid-cell-first" : ""}`}
                    style={{ width: widths[i], left: lefts[i] }}
                  >
                    <DisabledReason reason={reason}>
                      <button
                        type="button"
                        className="grid-sort"
                        aria-describedby={describedBy}
                        title={reason ? undefined : (spec.sortHint ?? hint?.text)}
                        onClick={() => cycleSort(spec)}
                      >
                        {spec.header}
                        <span aria-hidden="true" className="grid-sort-mark">
                          {sort === "ascending" ? "▲" : sort === "descending" ? "▼" : ""}
                        </span>
                      </button>
                    </DisabledReason>
                    {spec.sortHint ? (
                      <span id={`${hintPrefix}-${spec.id}`} hidden>
                        {spec.sortHint}
                      </span>
                    ) : null}
                    {hint ? (
                      <>
                        <span id={hintId} hidden>
                          {hint.text}
                        </span>
                        <EmptyHintLink hint={hint} hintId={hintId} />
                      </>
                    ) : null}
                    <div
                      aria-hidden="true"
                      className="grid-resizer"
                      onMouseDown={
                        column.getCanResize()
                          ? (e) => {
                              e.stopPropagation();
                              const start = e.clientX;
                              const startSize = column.getSize();
                              const min = spec.minWidth ?? 60;
                              const move = (ev: MouseEvent) =>
                                setColumnSizing((prev) => ({
                                  ...prev,
                                  [column.id]: Math.max(min, startSize + ev.clientX - start),
                                }));
                              const up = () => {
                                document.removeEventListener("mousemove", move);
                                document.removeEventListener("mouseup", up);
                              };
                              document.addEventListener("mousemove", move);
                              document.addEventListener("mouseup", up);
                            }
                          : undefined
                      }
                    />
                  </div>
                );
              })}
            </div>
            {filterRowShown ? (
              <ColumnFilterRow
                specs={specs}
                widths={widths}
                lefts={lefts}
                selectWidth={SELECT_COL_WIDTH}
                height={rowHeight + 4}
                rowIndex={2}
                filters={columnFilters ?? []}
                onChange={onColumnFilter}
                suggestions={typeSuggestions.length ? { type: typeSuggestions } : undefined}
              />
            ) : null}
          </div>
          <div role="rowgroup" className="grid-body" style={{ height: virtualizer.getTotalSize() }}>
            {virtualItems.map((item) => {
              const row = getDisplayRow(item.index);
              return (
                <RowView
                  key={row ? row.rowKey : `loading:${item.index}`}
                  row={row}
                  index={item.index}
                  top={item.start}
                  height={item.size}
                  selected={!!row && selectedKeys.has(row.rowKey)}
                  focused={item.index === clampedFocus}
                  specs={specs}
                  widths={widths}
                  lefts={lefts}
                  onMenuButton={onMenuButton}
                  menuOpen={menuAnchor !== null && menuRow === item.index}
                  menuId={menuId}
                  onToggle={onToggleCheckbox}
                  ariaRowOffset={headRows + 1}
                />
              );
            })}
          </div>
        </div>
        {displayCount === 0 && !cq.isLoading ? <p className="grid-empty">{emptyMessage}</p> : null}
        {displayCount === 0 && cq.isLoading && runId ? (
          // A typed / server-filtered page can scan for seconds: never a blank grid meanwhile.
          <p className="grid-empty grid-loading" data-testid="grid-loading">
            {loadingMessage}
          </p>
        ) : null}
      </div>

      <GridFooter
        page={currentPage}
        pageCount={cq.pageCount}
        total={cq.total}
        shown={displayCount}
        backend={cq.backend}
        elapsedMs={cq.elapsedMs}
        truncated={cq.truncated}
        filtering={needle !== ""}
        sorting={clientSorting}
        loadedCount={cq.loadedCount}
        canLoadMore={compactMode && cq.canLoadMore}
        serverPathFilter={ref.id === "artifacts" ? serverPathFilter(q) : undefined}
        scanned={cq.scanned}
        onLoadMore={loadMore}
        loading={cq.isFetching}
        scope={cq.category ? categoryScopeText(cq.category) : undefined}
      />
      {extractResult ? (
        <section className="grid-extract" role="status" aria-label="추출 결과">
          <strong>
            추출 {formatCount(extractResult.summary.extracted_count)}건 / 선택{" "}
            {formatCount(extractResult.summary.selected_count)}건
            {extractResult.summary.skipped_count > 0
              ? ` · 건너뜀 ${formatCount(extractResult.summary.skipped_count)}건`
              : ""}
          </strong>
          {extractResult.skipped.slice(0, 3).map((item) => (
            <span key={item.original_path} className="grid-note">
              {item.original_path}: {item.reason}
            </span>
          ))}
          <button
            type="button"
            className="grid-btn"
            disabled={extractResult.summary.extracted_count === 0}
            onClick={() => {
              downloadFile(extractResult.download_url, `${extractResult.name}.zip`).catch((error: unknown) =>
                toast.show(
                  `내려받기에 실패했습니다. ${error instanceof Error ? error.message : ""}`,
                  "error",
                ),
              );
            }}
          >
            ZIP 내려받기
          </button>
          <button type="button" className="grid-btn grid-btn-quiet" onClick={() => setExtractResult(null)}>
            닫기
          </button>
        </section>
      ) : null}
      <RowMenu
        id={menuId}
        anchor={menuAnchor}
        context={context}
        onClose={() => {
          setMenuAnchor(null);
          setMenuRow(null);
          returnToGrid();
        }}
        onDisabled={(reason) => toast.show(reason, "info")}
      />
      <div className="grid-toasts">
        {toast.toasts.map((t) => (
          <div key={t.id} className={`grid-toast is-${t.tone}`}>
            <span>{t.message}</span>
            <button type="button" className="grid-btn grid-btn-quiet" onClick={() => toast.dismiss(t.id)}>
              닫기
            </button>
          </div>
        ))}
      </div>
    </section>
  );
}
