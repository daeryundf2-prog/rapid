// biome-ignore-all lint/a11y/useSemanticElements: virtualized ARIA grid; rows are positioned divs, not a <table>
// biome-ignore-all lint/a11y/useFocusableInteractive: roving tabindex; only the focused row is focusable by design
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
  useMemo,
  useRef,
  useState,
} from "react";
import { announce } from "../../a11y";
import { downloadFile } from "../../api/client";
import type { RunExtractResult } from "../../api/extract";
import type { CollectionRef, GridRow } from "../../contracts/collection";
import type { CommandContext } from "../../contracts/command";
import { useDensity, useRoute, useSelection, useToast, useViewerTarget } from "./adapter";
import { BatchBar } from "./BatchBar";
import { collectionDef, presetColumnIds } from "./columns";
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
import { categoryScopeText, PAGE_SIZE, useCollectionQuery } from "./useCollectionQuery";
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
  onToggle: (index: number, checked: boolean) => void;
}

const RowView = memo(function RowView(props: RowViewProps) {
  const { row, index, top, height, selected, focused, specs, widths, lefts } = props;
  const style = { transform: `translateY(${top}px)`, height };
  if (!row) {
    return (
      <div
        role="row"
        aria-rowindex={index + 2}
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
      aria-rowindex={index + 2}
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
            title={text}
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
  const columns = useMemo(() => def.columnsFor?.(ref) ?? def.columns, [def, columnKey]);
  const q = route.q;
  const { density, setDensity } = useDensity();
  const rowHeight = DENSITY_ROW_HEIGHT[density];
  const selection = useSelection();
  const viewer = useViewerTarget();
  const toast = useToast();

  const [preset, setPreset] = useState<GridPreset>(() => readPreset(props.initialPreset ?? "analysis"));
  const [visibility, setVisibility] = useState<VisibilityState>(() => visibilityFor(columns, preset));
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnSizing, setColumnSizing] = useState<ColumnSizingState>({});
  const [focusIdx, setFocusIdx] = useState(0);
  const [menuAnchor, setMenuAnchor] = useState<Anchor>(null);
  const [tagPromptOpen, setTagPromptOpen] = useState(false);
  const [extractResult, setExtractResult] = useState<RunExtractResult | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  const filterRef = useRef<HTMLInputElement>(null);
  const anchorRef = useRef<number | null>(null);
  const wantDomFocus = useRef(false);
  const userNavigated = useRef(false);
  const restoredRow = useRef(false);

  const cq = useCollectionQuery(
    { ref, offset: 0, limit: PAGE_SIZE, text: q || undefined, search: route.search },
    { runId },
  );

  // Preset / collection change resets the column model and view state.
  const collectionKey = `${ref.id}:${ref.kind ?? ""}:${ref.status ?? ""}:${ref.category ?? ""}`;
  // biome-ignore lint/correctness/useExhaustiveDependencies: reset only when the collection or preset changes
  useEffect(() => {
    setVisibility(visibilityFor(columns, preset));
  }, [collectionKey, preset]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: reset only when the collection changes
  useEffect(() => {
    setSorting([]);
    setColumnSizing({});
    setFocusIdx(0);
    anchorRef.current = null;
    restoredRow.current = false;
  }, [collectionKey, runId]);

  const needle = q.trim();
  const compactMode = needle !== "" || sorting.length > 0;

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
  const displayCount = compactMode ? displayRows.length : (cq.total ?? cq.loadedCount);
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

  // Deep link: restore `row=` (focus + scroll) once, resolving the server page from the locator.
  useEffect(() => {
    const target = route.rowRef;
    if (!target || restoredRow.current || compactMode) return;
    const idx = indexFromRef(target);
    if (idx === null) {
      restoredRow.current = true;
      return;
    }
    ensureRange(idx, idx);
    const row = cq.getRow(idx);
    if (row) {
      restoredRow.current = true;
      setFocusIdx(idx);
      virtualizer.scrollToIndex(idx, { align: "center" });
    }
  }, [route.rowRef, compactMode, ensureRange, cq.getRow, virtualizer]);

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
        setMenuAnchor({ x: (rect?.left ?? 0) + SELECT_COL_WIDTH, y: rect?.bottom ?? 0 });
      });
    }
  };

  const onRowMouseDown = (event: ReactMouseEvent<HTMLDivElement>) => {
    const rowEl = (event.target as HTMLElement).closest<HTMLElement>("[data-index]");
    if (!rowEl || (event.target as HTMLElement).closest("input, button")) return;
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
    setMenuAnchor({ x: event.clientX, y: event.clientY });
  };

  const onMenuButton = useCallback((index: number, target: HTMLElement) => {
    setFocusIdx(index);
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

  const announcement = useMemo(() => {
    if (cq.isLoading || !runId) return "";
    return resultSentence(compactMode ? displayCount : (cq.total ?? displayCount), cq.backend, cq.elapsedMs);
  }, [cq.isLoading, runId, compactMode, displayCount, cq.total, cq.backend, cq.elapsedMs]);

  // Only S5's announce() creates live regions: one sentence per result change.
  useEffect(() => {
    if (announcement) announce(announcement);
  }, [announcement]);

  const lastToast = toast.toasts.at(-1);
  useEffect(() => {
    if (lastToast)
      announce(lastToast.message, { politeness: lastToast.tone === "error" ? "assertive" : "polite" });
  }, [lastToast]);

  const sortOf = (id: string): "ascending" | "descending" | "none" => {
    const s = sorting.find((item) => item.id === id);
    return s ? (s.desc ? "descending" : "ascending") : "none";
  };
  const cycleSort = (id: string) => {
    const current = sortOf(id);
    setSorting(
      current === "none" ? [{ id, desc: false }] : current === "ascending" ? [{ id, desc: true }] : [],
    );
    setFocusIdx(0);
  };

  const rowCountAria = (compactMode ? displayCount : (cq.total ?? -1)) + 1;
  const currentPage = Math.min(cq.pageCount ?? 1, Math.floor(firstVisible / cq.pageSize) + 1);

  const emptyMessage = !runId
    ? "케이스를 먼저 선택하세요."
    : ref.id === "intake"
      ? "접수 요약은 그리드가 아닌 요약 화면에서 확인합니다."
      : ref.id === "search" && !(route.search && route.search.keywords.length > 0)
        ? "검색어를 입력하면 결과가 여기에 표시됩니다."
        : compactMode
          ? "조건에 맞는 행이 없습니다. 불러온 행 안에서만 필터합니다."
          : "표시할 행이 없습니다.";

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
        style={{ scrollPaddingLeft: SELECT_COL_WIDTH + stickyWidth, scrollPaddingTop: rowHeight }}
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
                const sort = sortOf(column.id);
                return (
                  <div
                    key={column.id}
                    role="columnheader"
                    aria-sort={sort}
                    data-col={column.id}
                    className={`grid-cell grid-hcell${lefts[i] !== undefined ? " grid-cell-first" : ""}`}
                    style={{ width: widths[i], left: lefts[i] }}
                  >
                    <button type="button" className="grid-sort" onClick={() => cycleSort(column.id)}>
                      {spec.header}
                      <span aria-hidden="true" className="grid-sort-mark">
                        {sort === "ascending" ? "▲" : sort === "descending" ? "▼" : ""}
                      </span>
                    </button>
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
                  onToggle={onToggleCheckbox}
                />
              );
            })}
          </div>
        </div>
        {displayCount === 0 && !cq.isLoading ? <p className="grid-empty">{emptyMessage}</p> : null}
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
        sorting={sorting.length > 0}
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
        anchor={menuAnchor}
        context={context}
        onClose={() => {
          setMenuAnchor(null);
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
