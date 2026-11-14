// biome-ignore-all lint/a11y/useSemanticElements: virtualized ARIA grid; rows are positioned divs, not a <table>
// biome-ignore-all lint/a11y/useFocusableInteractive: roving tabindex; only the focused row is focusable by design

import { defaultRangeExtractor, type Range, useVirtualizer } from "@tanstack/react-virtual";
import {
  memo,
  type ReactNode,
  type RefObject,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useSyncExternalStore,
} from "react";
import type { GridRow } from "../../contracts/collection";
import { Icon } from "../../icons";
import { REVIEW_LABELS } from "./columns/common";
import { displayText } from "./gridUtils";
import type { ColumnSpec } from "./types";

/** Checkbox 16 + gap 4 + row-menu button 20 + padding 2×8. */
export const SELECT_COL_WIDTH = 56;
/** Rows rendered beyond the viewport on each side. */
const OVERSCAN = 12;

/** Review mark shown as the row stripe (U-F8): the review status, else a 북마크 tag. */
export function rowMark(row: GridRow): { id: string; label: string } | null {
  if (row.reviewStatus) return { id: row.reviewStatus, label: REVIEW_LABELS[row.reviewStatus] };
  if (row.tags.some((tag) => tag === "북마크" || tag === "bookmark"))
    return { id: "bookmark", label: "북마크" };
  return null;
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
  /** Checkbox click: toggle this row only (`range`: Shift held, extend from the anchor). */
  onToggle: (index: number, checked: boolean, range: boolean) => void;
  /** aria-rowindex of data row 0 (2, or 3 under the column filter row). */
  ariaRowOffset: number;
  /**
   * What the cells read outside their props (display timezone · family catalogue version): rows
   * are memoized, so a change here is what re-renders them (time cells, flag chips).
   */
  cellEpoch: string;
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
  const mark = rowMark(row);
  return (
    <div
      role="row"
      aria-rowindex={index + props.ariaRowOffset}
      aria-selected={selected}
      tabIndex={focused ? 0 : -1}
      data-index={index}
      data-row-key={row.rowKey}
      data-mark={mark?.id}
      aria-description={mark ? `검토 표시: ${mark.label}` : undefined}
      className={`grid-row${selected ? " is-selected" : ""}${focused ? " is-focused" : ""}`}
      style={style}
    >
      <div role="gridcell" className="grid-cell grid-cell-select" style={{ width: SELECT_COL_WIDTH }}>
        {/* U-F8: 6px review stripe on the sticky select cell (visible while scrolling sideways). */}
        {mark ? <span className="grid-row-stripe" data-mark={mark.id} aria-hidden="true" /> : null}
        <input
          type="checkbox"
          tabIndex={-1}
          aria-label={`${row.title || "행"} 선택`}
          checked={selected}
          onChange={(event) =>
            props.onToggle(
              index,
              event.target.checked,
              (event.nativeEvent as MouseEvent | undefined)?.shiftKey === true,
            )
          }
          // The checkbox never activates the row (row click = move the focused row only).
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
          <Icon name="more" />
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
            {spec.render ? (
              spec.render(row)
            ) : text ? (
              <span className="grid-cell-text">{text}</span>
            ) : (
              // Empty value: a muted dash, never a blank cell (visual-polish B2 #2).
              <span className="grid-cell-empty" aria-hidden="true">
                —
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
});

/**
 * The first visible row index, published by GridBody for readers outside it (the footer's page
 * number): a subscriber re-renders when it changes, the grid around the rows does not.
 */
export interface VisibleStart {
  get: () => number;
  set: (index: number) => void;
  subscribe: (listener: () => void) => () => void;
}

export function createVisibleStart(): VisibleStart {
  let value = 0;
  const listeners = new Set<() => void>();
  return {
    get: () => value,
    set: (index) => {
      if (index === value) return;
      value = index;
      for (const listener of listeners) listener();
    },
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

/** A value derived from the first visible row (e.g. its page); re-renders only when it changes. */
export function useVisibleStart<T>(source: VisibleStart, select: (first: number) => T): T {
  return useSyncExternalStore(source.subscribe, () => select(source.get()));
}

/** Renders `children` with the 1-based page of the first visible row (re-renders on page change only). */
export function VisiblePage(props: {
  source: VisibleStart;
  pageSize: number;
  pageCount: number | null;
  children: (page: number) => ReactNode;
}) {
  const { pageSize, pageCount } = props;
  const page = useVisibleStart(props.source, (first) =>
    Math.min(pageCount ?? 1, Math.floor(first / pageSize) + 1),
  );
  return <>{props.children(page)}</>;
}

/** What the grid asks of its rows from outside (keyboard moves, deep links, PageUp/PageDown). */
export interface GridBodyHandle {
  scrollToIndex: (index: number, align: "auto" | "center") => void;
  /** Rows in the viewport (without the overscan); 10 before the first layout. */
  pageRows: () => number;
}

export interface GridBodyProps {
  scrollRef: RefObject<HTMLDivElement | null>;
  /** Filled while mounted: the grid scrolls rows into view through it. */
  handleRef: { current: GridBodyHandle | null };
  /** First visible row index (footer page number). */
  visibleStart: VisibleStart;
  count: number;
  rowHeight: number;
  /** Focused row index (-1 = none); it stays rendered even when scrolled away. */
  focusIdx: number;
  /** Row key held across a re-sort (C-D2); while set, only that row may show as focused. */
  sortHold: string | null;
  /** The focused row is loaded (DOM focus waits for it). */
  focusReady: boolean;
  /** Set by keyboard navigation: DOM focus follows the focused row once it is rendered. */
  wantDomFocus: { current: boolean };
  getRow: (index: number) => GridRow | undefined;
  selectedKeys: ReadonlySet<string>;
  specs: ColumnSpec[];
  widths: number[];
  lefts: (number | undefined)[];
  cellEpoch: string;
  ariaRowOffset: number;
  /** Row index whose menu is open (null = none). */
  menuRow: number | null;
  menuId: string;
  onMenuButton: (index: number, target: HTMLElement) => void;
  onToggle: (index: number, checked: boolean, range: boolean) => void;
  /** Filtered / client-sorted rows (load more near the end) vs random access (load the viewport's pages). */
  compactMode: boolean;
  ensureRange: (start: number, end: number) => void;
  loadMore: () => void;
  canLoadMore: boolean;
}

/**
 * The virtualized rows. Scrolling re-renders this component only — the toolbar, header, banners
 * and footer around it keep their last render (each scroll frame used to re-render all of them).
 */
export const GridBody = memo(function GridBody(props: GridBodyProps) {
  const { scrollRef, count, rowHeight, focusIdx, compactMode, ensureRange, loadMore, canLoadMore } = props;
  // The extractor identity changes with the focused row so the virtualizer recomputes and keeps it mounted.
  const rangeExtractor = useCallback(
    (range: Range) => {
      const base = defaultRangeExtractor(range);
      if (focusIdx >= 0 && !base.includes(focusIdx)) return [...base, focusIdx].sort((a, b) => a - b);
      return base;
    },
    [focusIdx],
  );
  const virtualizer = useVirtualizer({
    count,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan: OVERSCAN,
    rangeExtractor,
    initialRect: { width: 1000, height: 600 },
  });
  // A new row height (density, AXIOM preset) drops the cached row sizes.
  // biome-ignore lint/correctness/useExhaustiveDependencies: re-measure only when the height changes
  useEffect(() => {
    virtualizer.measure();
  }, [rowHeight]);
  const virtualItems = virtualizer.getVirtualItems();
  // `range` excludes the always-rendered focused row, so jumping (End) does not request every page in between.
  const firstVisible = virtualizer.range?.startIndex ?? 0;
  const lastVisible = virtualizer.range?.endIndex ?? 0;

  const rendered = useRef({ first: firstVisible, last: lastVisible, items: virtualItems.length });
  rendered.current = { first: firstVisible, last: lastVisible, items: virtualItems.length };
  const { handleRef, visibleStart } = props;
  // Layout effect: the grid's own effects (deep-link restore) run after this and may scroll.
  useLayoutEffect(() => {
    handleRef.current = {
      scrollToIndex: (index, align) => virtualizer.scrollToIndex(index, { align }),
      pageRows: () => {
        const { first, last, items } = rendered.current;
        return Math.max(1, items > 4 ? last - first - OVERSCAN : 10);
      },
    };
    return () => {
      handleRef.current = null;
    };
  }, [handleRef, virtualizer]);
  useEffect(() => {
    visibleStart.set(firstVisible);
  }, [visibleStart, firstVisible]);

  // Random-access mode: request the server pages the viewport covers (+ prefetch next).
  useEffect(() => {
    if (!compactMode) ensureRange(firstVisible, lastVisible);
  }, [compactMode, ensureRange, firstVisible, lastVisible]);

  // Compact mode: near the end, after the user scrolled, pull the next page.
  useEffect(() => {
    if (!compactMode) return;
    const scrolled = (scrollRef.current?.scrollTop ?? 0) > 0;
    if (scrolled && lastVisible >= count - 15 && canLoadMore) {
      loadMore();
    }
  }, [compactMode, lastVisible, count, canLoadMore, loadMore, scrollRef]);

  // Move DOM focus onto the focused row after keyboard navigation (rows are virtualized).
  const { wantDomFocus, focusReady } = props;
  const itemSignature = `${firstVisible}-${lastVisible}-${focusIdx}-${focusReady ? 1 : 0}`;
  // biome-ignore lint/correctness/useExhaustiveDependencies: runs when the rendered window changes
  useEffect(() => {
    if (!wantDomFocus.current || focusIdx < 0) return;
    const el = scrollRef.current?.querySelector<HTMLElement>(`[data-index="${focusIdx}"]`);
    if (el) {
      el.focus({ preventScroll: true });
      wantDomFocus.current = false;
    }
  }, [itemSignature, count]);

  const { getRow, selectedKeys, sortHold, menuRow } = props;
  return (
    <div role="rowgroup" className="grid-body" style={{ height: virtualizer.getTotalSize() }}>
      {virtualItems.map((item) => {
        const row = getRow(item.index);
        return (
          <RowView
            key={row ? row.rowKey : `loading:${item.index}`}
            row={row}
            index={item.index}
            top={item.start}
            height={item.size}
            selected={!!row && selectedKeys.has(row.rowKey)}
            focused={item.index === focusIdx && (sortHold === null || row?.rowKey === sortHold)}
            specs={props.specs}
            widths={props.widths}
            lefts={props.lefts}
            onMenuButton={props.onMenuButton}
            menuOpen={menuRow === item.index}
            menuId={props.menuId}
            onToggle={props.onToggle}
            ariaRowOffset={props.ariaRowOffset}
            cellEpoch={props.cellEpoch}
          />
        );
      })}
    </div>
  );
});
