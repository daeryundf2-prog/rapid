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
  type CSSProperties,
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
import { DOCS_MATCHED, locateTimelineRow } from "../../api/collections";
import type { RunExtractResult } from "../../api/extract";
import { getRunTree } from "../../api/runs";
import type { CollectionRef, GridRow } from "../../contracts/collection";
import type { CommandContext } from "../../contracts/command";
import { Icon } from "../../icons";
import { currentRun } from "../../state/slices/runs";
import { useAppStore } from "../../state/store";
import { runCommandId } from "../analysis/commands";
import { setColumnFilter } from "../filters/columnFilters";
import type { FilterBarVariant } from "../filters/FilterBar";
import { useFilterStore } from "../filters/filterStore";
import { noteKindTypeCounts, useCatalog } from "../flags/catalog";
import { flagsPartialNotice, flagsUnavailableReason, mergedKindNode, policyAbsences } from "../tree/model";
import { useDensity, useGridLocalStore, useRoute, useSelection, useToast, useViewerTarget } from "./adapter";
import { BatchBar, batchBarState } from "./BatchBar";
import { ColumnFilterRow } from "./ColumnFilterRow";
import { collectionDef, lockedColumnId, presetColumnIds } from "./columns";
import { analysisFamily } from "./columns/analysis";
import { artifactTypeFamily, resolveArtifactFamily } from "./columns/artifacts";
import { growWeight, isRecord, REVIEW_LABELS } from "./columns/common";
import { auxColumnIds } from "./columns/families";
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
import { FILES_SERVER_SORT_KEYS, ntfsJoinOf, runInputIsImage } from "./columns/files";
import { EmptyHintLink } from "./EmptyHintLink";
import { GridEmpty, type GridEmptyState } from "./GridEmpty";
import { ColumnMenu, DocsMatchedToggle, GridFooter, GridToolbar } from "./GridToolbar";
import { buildViewerTarget, type GridCommandHost, runBatch, runNote, useGridCommands } from "./gridCommands";
import {
  type AutoHideReason,
  compareValues,
  displayText,
  emptyColumnIds,
  fitColumnWidths,
  formatCount,
  indexFromRef,
  matchesFilter,
  priorityHiddenColumns,
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

/** Checkbox 16 + gap 4 + row-menu button 20 + padding 2×8. */
const SELECT_COL_WIDTH = 56;
/** The column menu moved to the 조건 줄 (U-F1): the header keeps no room for it. */
const HEAD_TOOLS_WIDTH = 0;
/** The header row is 32px at every density (visual-polish U-V4); rows follow the density. */
const HEADER_HEIGHT = 32;
const EMPTY_ROWS: GridRow[] = [];
/** Skeleton rows while the first page loads (review #11). */
const SKELETON_ROWS = [1, 2, 3, 4, 5, 6, 7, 8];
const PRESETS: readonly GridPreset[] = ["analysis", "compact", "source", "axiom"];
/** AXIOM preset (X13): the tag/status chip column is pinned right after the select cell. */
const AXIOM_PINNED = "tagstatus";

/** Header-sort reasons on the artifacts grid (server sort only; no silent "loaded rows only" sort). */
export const SORT_COLUMN_REASON = "이 열은 전체 정렬을 지원하지 않습니다";
/** Header note of a family core column with no value in any loaded row (kept, not hidden). */
export const KEPT_EMPTY_COLUMN_NOTE = "이 페이지 값 없음";
/**
 * A timeline written before the readability builder (UX-round review). There is no regenerate
 * action in the console yet, so the hint says what regenerating would change; nothing rebuilds
 * automatically.
 */
export const TIMELINE_LEGACY_HINT =
  "이 런의 타임라인은 이전 형식입니다 — 다시 생성하면 요약·중복 제거가 적용됩니다";
export const SORT_KIND_REASON = "유형을 하나 선택하면 전체 정렬할 수 있습니다";
export const SORT_ANALYSIS_REASON = "분석 결과를 선택하면 전체 정렬할 수 있습니다";
/**
 * Range honesty (plan r7 §3.2 L2, C-D1 / 구조 D2): a paged grid sorted or filtered on the client
 * covers the loaded rows only — this banner says so whenever that is the case.
 */
export const CLIENT_SCOPE_BANNER = "정렬·필터는 불러온 행 기준";
/** Header tooltip of a column the server cannot sort on a paged grid. */
export const CLIENT_SORT_HINT = "불러온 행만 정렬합니다 (전체 정렬은 지원하지 않는 열)";
/** Collections whose all-empty default columns hide (like the files list; C-D7, C-D11, C-E4). */
const EMPTY_HIDE_COLLECTIONS: ReadonlySet<string> = new Set(["files", "artifacts", "docs", "analysis"]);
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
  const locked = lockedColumnId(columns);
  return Object.fromEntries(columns.map((c) => [c.id, c.id === locked || visible.has(c.id)]));
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
}

/** Review mark shown as the row stripe (U-F8): the review status, else a 북마크 tag. */
export function rowMark(row: GridRow): { id: string; label: string } | null {
  if (row.reviewStatus) return { id: row.reviewStatus, label: REVIEW_LABELS[row.reviewStatus] };
  if (row.tags.some((tag) => tag === "북마크" || tag === "bookmark"))
    return { id: "bookmark", label: "북마크" };
  return null;
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

export function DataGrid(props: DataGridProps = {}) {
  const route = useRoute();
  const runId = props.runId !== undefined ? props.runId : route.runId;
  const ref = props.collection ?? route.collection;
  const def = collectionDef(ref.id);
  // A 유형 filter of one artifact-type family (다운로드 · USB · SAM …) picks that family's columns.
  const filterTypes = useFilterStore((s) => s.filters.types);
  const typeFamily = ref.id === "artifacts" ? (artifactTypeFamily(filterTypes) ?? "") : "";
  // The catalogue (bundled fallback, then the server's) picks family layouts: a new one rebuilds them.
  const catalog = useCatalog();
  // Shared with the tree (same query key): the run's artifact types (exact server values) for the
  // 유형 menu and the 유형(정확히) suggestions — loaded rows alone shrink once a 유형 filter applies.
  // Its per-kind type counts also give a kind the catalogue reaches only through its types (or a
  // mixed kind) its majority family layout (U-F3).
  const runTree = useQuery({
    queryKey: ["run-tree", runId],
    queryFn: () => getRunTree(runId as string),
    enabled: Boolean(runId) && ref.id === "artifacts",
    retry: false,
    staleTime: 30_000,
  });
  if (ref.id === "artifacts" && ref.kind) {
    noteKindTypeCounts(ref.kind, mergedKindNode(runTree.data, ref.kind)?.artifact_type_counts);
  }
  // Analysis rows (R3 §3.3): the node's `f:source` server filter (타임스탬프 불일치, $LogFile), the
  // carve job, or the loaded rows' one artifact-type family picks catalogue columns too.
  const routeColumnFilters = useFilterStore((s) => s.filters.columns);
  // Artifacts (and analysis job rows) are sorted by the server (whole kind / whole job), never
  // client-side over the loaded pages.
  const isAnalysis = ref.id === "analysis";
  // 파일 목록: 이름 · 경로 · 크기 · 수정 · NTFS 생성 · 특이사항 sort the whole list on the server
  // (files column index, plan r7 §3.2 L2); every other column sorts the loaded rows (banner).
  const filesGrid = ref.id === "files";
  const serverSorted = ref.id === "artifacts" || isAnalysis || filesGrid;
  /** The kind whose columns / sort / promoted fields apply; for analysis only once a job is selected. */
  const artifactKind =
    ref.id === "artifacts" ? ref.kind : isAnalysis && ref.analysisId ? ref.kind : undefined;
  /** Promoted-column storage scope ("analysis:<kind>" keeps analysis kinds apart from artifact kinds). */
  const fieldScope = artifactKind ? (isAnalysis ? `analysis:${artifactKind}` : artifactKind) : undefined;
  /** RowRef.kind of this grid's rows: the artifact kind, or the analysis job id. */
  const rowKindOfGrid = isAnalysis ? ref.analysisId : ref.kind;
  const routeSort = artifactKind || filesGrid ? route.sort : undefined;
  // Promoted record-field columns (URL `cols=`, else the kind's stored set); kept across presets.
  const promotedCols = useMemo(() => effectiveFieldCols(route.cols, fieldScope), [route.cols, fieldScope]);
  const promotedKeys = useMemo(() => colsToKeys(promotedCols), [promotedCols]);
  const q = route.q;
  // Timeline (timeline/grid readability C3 / C1): the text box searches every event on the server
  // (`q=`), and events of one target · second · kind of time are one row unless ungrouped. The
  // files list filters name/path on the server too (`q=`, plan r7 §3.2 L2).
  const serverSearch = ref.id === "timeline";
  const serverText = serverSearch || filesGrid;
  const serverQuery = serverSearch ? q.trim() : "";
  const [timelineGrouped, setTimelineGrouped] = useState(true);
  const treeTypes = useMemo(
    () => (ref.id === "artifacts" ? artifactTypesOfTree(runTree.data?.nodes, ref.kind) : []),
    [ref.id, ref.kind, runTree.data],
  );
  const cq = useCollectionQuery(
    {
      ref,
      offset: 0,
      limit: PAGE_SIZE,
      text: q || undefined,
      search: route.search,
      sort: routeSort,
      ...(serverSearch ? { group: timelineGrouped } : {}),
    },
    { runId, typeOptions: treeTypes },
  );
  const analysisRowTypesSig =
    ref.id === "analysis" && ref.analysisId
      ? [...new Set(cq.loadedRows.map((row) => row.artifactType ?? ""))].sort().join(",")
      : "";
  const analysisRowTypes = useMemo(
    () => (analysisRowTypesSig ? analysisRowTypesSig.split(",") : []),
    [analysisRowTypesSig],
  );
  const family =
    ref.id === "artifacts"
      ? resolveArtifactFamily(ref.kind, filterTypes)
      : ref.id === "analysis" && ref.analysisId
        ? analysisFamily(ref.kind, routeColumnFilters, analysisRowTypes)
        : undefined;
  const familyId = family?.id ?? "";
  const columnKey = `${ref.id}:${ref.kind ?? ""}:${ref.analysisId ?? ""}:${typeFamily}:${familyId}:${catalog.version}`;
  // biome-ignore lint/correctness/useExhaustiveDependencies: columns only depend on the collection/kind/family
  const baseColumns = useMemo(
    () =>
      def.columnsFor?.(ref, filterTypes, { columnFilters: routeColumnFilters, rowTypes: analysisRowTypes }) ??
      def.columns,
    [def, columnKey],
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
  const selection = useSelection();
  const viewer = useViewerTarget();
  const toast = useToast();

  const [preset, setPreset] = useState<GridPreset>(() => readPreset(props.initialPreset ?? "analysis"));
  // AXIOM's two-line titles need at least the roomy 32px row; that is a property of the preset,
  // not a change of the global density preference (review nit).
  const rowHeight = Math.max(
    DENSITY_ROW_HEIGHT[density],
    preset === "axiom" ? DENSITY_ROW_HEIGHT.comfortable : 0,
  );
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
  /** Default columns the user showed explicitly: never hidden for width / missing values. */
  const [pinnedColumns, setPinnedColumns] = useState<ReadonlySet<string>>(() => new Set());
  const [focusIdx, setFocusIdx] = useState(0);
  /**
   * A header click re-sorts only (C-D2): the focused row (its key) is held across the new order —
   * focus, viewer and `row=` stay on it; it is re-found among the loaded rows when it is there,
   * and nothing else gets focus meanwhile. Any navigation by the analyst ends the hold.
   */
  const [sortHold, setSortHold] = useState<string | null>(null);
  const [menuAnchor, setMenuAnchor] = useState<Anchor>(null);
  /** Row index whose menu is open (trigger aria-expanded / aria-controls). */
  const [menuRow, setMenuRow] = useState<number | null>(null);
  const menuId = useId();
  const [tagPromptOpen, setTagPromptOpen] = useState(false);
  const [extractResult, setExtractResult] = useState<RunExtractResult | null>(null);
  /** Last server-sort refusal ("unsupported"), shown in the sort status line until the next sort. */
  const [sortNotice, setSortNotice] = useState<string | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  // Visible grid width (for fitColumnWidths); 0 until measured (and in jsdom).
  const [paneWidth, setPaneWidth] = useState(0);
  /** Rendered height of the floating batch bar (0 = hidden); the rows keep that much room free. */
  const [batchHeight, setBatchHeight] = useState(0);
  useEffect(() => {
    const el = scrollRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const measure = () => setPaneWidth(el.clientWidth);
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    measure();
    return () => observer.disconnect();
  }, []);
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
    setPinnedColumns(new Set());
  }, [collectionKey, preset, typeFamily, familyId, catalog]);
  // 파일 시스템 탐색기: another folder is another listing (focus / selection), same columns.
  const listingKey = `${collectionKey}:${ref.dir ?? ""}:${ref.recursive ? "r" : ""}:${ref.special ?? ""}`;
  // Reset only when the collection (or the explorer folder) changes.
  useEffect(() => {
    setSorting([]);
    setSortNotice(null);
    setColumnSizing({});
    setSortHold(null);
    setFocusIdx(0);
    anchorRef.current = null;
    restoredRow.current = false;
    // Focus is identified by the route's RowRef, never by a stale position: a new collection
    // starts unnavigated, so the automatic first-row focus never rewrites `row=`.
    userNavigated.current = false;
    // The selection belongs to one grid: another collection / stage / run starts empty (a
    // remount of the same grid — e.g. the layout switching to the drawer — keeps it).
    useGridLocalStore.getState().enterSelectionScope(`${runId ?? ""}|${listingKey}`);
  }, [listingKey, runId]);
  // Server order / server path filter changed: positions mean other records now. Re-resolve the
  // focused row from the route's `row=` (locate= under a server sort), else fall back to row 0.
  const orderKey = serverSorted
    ? `${routeSort ? `${routeSort.key}:${routeSort.order}` : ""}|${serverPathFilter(q) ?? ""}`
    : "";
  const lastOrderKey = useRef(orderKey);
  const sortHoldRef = useRef(sortHold);
  sortHoldRef.current = sortHold;
  useEffect(() => {
    if (lastOrderKey.current === orderKey) return;
    lastOrderKey.current = orderKey;
    anchorRef.current = null;
    // A header click holds the focused row (C-D2): no deep-link restore, no jump to row 0.
    if (sortHoldRef.current !== null) return;
    userNavigated.current = false;
    restoredRow.current = false;
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

  // A server-searched listing (timeline) never re-filters its rows by the text on the client.
  const needle = serverText ? "" : q.trim();
  const clientSorting = sorting.length > 0;
  const compactMode = needle !== "" || clientSorting;

  const filtered = useMemo(
    () => (needle ? cq.loadedRows.filter((row) => matchesFilter(row, needle)) : cq.loadedRows),
    [cq.loadedRows, needle],
  );

  // AXIOM preset: chip column first (pinned after the select cell), then the two-line title.
  const orderedColumns = useMemo(() => {
    if (preset !== "axiom") return columns;
    const pinned = columns.find((c) => c.id === AXIOM_PINNED);
    const title = columns.find((c) => c.id === "title");
    const lead = [pinned, title].filter((c): c is ColumnSpec => Boolean(c));
    return [...lead, ...columns.filter((c) => !lead.includes(c))];
  }, [columns, preset]);

  // Responsive default layout (분석 기본 preset only): a default column with no value in any
  // loaded row goes (시각, 선별 … — review #9), then the lowest-priority columns go while their
  // minimum widths exceed the grid width. 항목 (the first priority id) always stays.
  const widthPriority = preset === "analysis" ? def.widthPriority?.(ref, filterTypes) : undefined;
  // Core columns of the grid's family are never hidden for one page without values (P1).
  const keepWhenEmptySig = (def.keepWhenEmpty?.(ref, filterTypes) ?? []).join("|");
  const loadedRows = cq.loadedRows;
  // The NTFS columns' "실행" hint applies to image inputs only (C-D12): a folder input's empty
  // NTFS columns hide like any other empty column.
  const runRecord = useAppStore((s) => currentRun(s));
  const inputIsImage = runInputIsImage(runRecord);
  // Columns the analyst is working with — sorted or column-filtered — never hide (C-D2).
  const sortedColumnId = routeSort ? columns.find((c) => c.sortKey === routeSort.key)?.id : sorting[0]?.id;
  const activeSig = [sortedColumnId ?? "", ...(columnFilters ?? []).map((f) => f.col)].join("|");
  const keepShown = useMemo(() => {
    const out = new Set(pinnedColumns);
    for (const id of activeSig.split("|")) if (id) out.add(id);
    return out;
  }, [pinnedColumns, activeSig]);
  // Empty default columns hide on every family / kind layout (C-D7): the width priority's
  // columns, else (kind layouts without one) every default column but 항목.
  const emptyCandidates = useMemo(() => {
    if (preset !== "analysis") return [];
    if (widthPriority) return widthPriority.slice(1);
    if (!EMPTY_HIDE_COLLECTIONS.has(ref.id)) return [];
    return orderedColumns
      .filter((c, i) => i > 0 && c.id !== "title" && visibility[c.id] !== false)
      .map((c) => c.id);
  }, [preset, widthPriority, ref.id, orderedColumns, visibility]);
  const emptyIds = useMemo(() => {
    if (emptyCandidates.length === 0) return [];
    const keep = new Set(keepWhenEmptySig ? keepWhenEmptySig.split("|") : []);
    return emptyColumnIds(orderedColumns, loadedRows, {
      candidates: emptyCandidates.filter((id) => !keep.has(id)),
      keep: keepShown,
      ignoreHints: ref.id === "files" && !inputIsImage,
    });
  }, [emptyCandidates, keepWhenEmptySig, orderedColumns, loadedRows, keepShown, ref.id, inputIsImage]);
  // A core column kept although no loaded row has a value says so in its header (UX-round review):
  // the column stays (the next page may fill it), the blank is explained.
  const keptEmptyIds = useMemo(() => {
    if (!keepWhenEmptySig) return new Set<string>();
    return new Set(emptyColumnIds(orderedColumns, loadedRows, { candidates: keepWhenEmptySig.split("|") }));
  }, [keepWhenEmptySig, orderedColumns, loadedRows]);
  const autoHidden = useMemo(() => {
    const out = new Map<string, AutoHideReason>();
    for (const id of emptyIds) out.set(id, "empty");
    if (!widthPriority) return out;
    const shown = orderedColumns
      .filter((c) => visibility[c.id] !== false && !out.has(c.id))
      .map((c) => ({ id: c.id, min: columnSizing[c.id] ?? c.minWidth ?? c.width }));
    const hidden = priorityHiddenColumns(shown, {
      priority: widthPriority,
      available: paneWidth - SELECT_COL_WIDTH - HEAD_TOOLS_WIDTH,
      keep: keepShown,
    });
    for (const id of hidden) out.set(id, "width");
    return out;
  }, [widthPriority, emptyIds, keepShown, orderedColumns, visibility, columnSizing, paneWidth]);
  const tableVisibility = useMemo(() => {
    if (autoHidden.size === 0) return visibility;
    const next = { ...visibility };
    for (const id of autoHidden.keys()) next[id] = false;
    return next;
  }, [visibility, autoHidden]);
  const toggleColumn = useCallback((id: string, visible: boolean) => {
    // Showing a column is explicit: it stays on screen however narrow the grid gets.
    setPinnedColumns((prev) => {
      if (prev.has(id) === visible) return prev;
      const next = new Set(prev);
      if (visible) next.add(id);
      else next.delete(id);
      return next;
    });
    setVisibility((prev) => ({ ...prev, [id]: visible }));
  }, []);

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
    state: { sorting, columnVisibility: tableVisibility, columnSizing },
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
  // 항목 flexes into the pane width; nothing shrinks (a narrow grid hides default columns by
  // priority instead, see autoHidden). Widths the user dragged stay as dragged.
  // Spare width goes to the long-text columns by weight (항목 · 경로 · URL · 대상 …, C-D7); a
  // column the user resized keeps its width.
  const widths = fitColumnWidths(
    visibleColumns.map((c) => c.getSize()),
    {
      grow: columnSizing.title === undefined ? specs.findIndex((s) => s.id === "title") : -1,
      available: paneWidth - SELECT_COL_WIDTH - HEAD_TOOLS_WIDTH,
      weights: specs.map((s) => (columnSizing[s.id] === undefined ? growWeight(s) : 0)),
    },
  );
  // Publish the shown column ids (the meta tab's "기본 열에 이미 표시됩니다" checks them).
  const visibleSig = specs.map((s) => s.id).join("\n");
  useEffect(() => {
    const { setVisibleColumnIds } = useGridLocalStore.getState();
    setVisibleColumnIds(visibleSig ? visibleSig.split("\n") : []);
  }, [visibleSig]);
  useEffect(() => () => useGridLocalStore.getState().setVisibleColumnIds(null), []);
  // + room for the column-menu button over the header's right end (the last column scrolls clear of it).
  const totalWidth = SELECT_COL_WIDTH + widths.reduce((sum, w) => sum + w, 0) + HEAD_TOOLS_WIDTH;
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
  // A new row height (density, AXIOM preset) drops the cached row sizes.
  // biome-ignore lint/correctness/useExhaustiveDependencies: re-measure only when the height changes
  useEffect(() => {
    virtualizer.measure();
  }, [rowHeight]);
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

  const displayFocusedRow = clampedFocus >= 0 ? getDisplayRow(clampedFocus) : undefined;
  // While a re-sort holds the focused row and it is not (yet) found, no row is focused.
  const focusedRow =
    sortHold !== null && displayFocusedRow?.rowKey !== sortHold ? undefined : displayFocusedRow;
  const selectedKeys = selection.selectedKeys;

  // Re-find the held row in the new order (client sort: the sorted rows; server sort: the loaded
  // pages). Found: focus moves to its new index; the hold ends once that row is focused.
  const { indexOfKey } = cq;
  const heldIndex = useMemo(() => {
    if (sortHold === null) return -1;
    if (compactMode) return displayRows.findIndex((row) => row.rowKey === sortHold);
    return indexOfKey(sortHold);
  }, [sortHold, compactMode, displayRows, indexOfKey]);
  useEffect(() => {
    if (sortHold !== null && heldIndex >= 0) setFocusIdx(heldIndex);
  }, [sortHold, heldIndex]);

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
    if (sortHold !== null) {
      // Same row under a new order: the store, viewer and URL already point at it.
      if (focusedRow?.rowKey === sortHold) {
        lastPublished.current = focusedRow;
        setSortHold(null);
      }
      return;
    }
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
  }, [focusedRow, runId, setFocused, publishNow, publishFocusedRow, sortHold]);

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

  // Timeline deep link while grouped / searched / filtered: rows are not at their record index,
  // so the server says where the event's row is (`locate=` with the same query; C1 / C3).
  const timelineLocateTarget =
    ref.id === "timeline" && route.rowRef?.collection === "timeline" ? indexFromRef(route.rowRef) : null;
  const timelineConditions = cq.query.rowConditions;
  const timelineLocateKey =
    timelineLocateTarget !== null &&
    (timelineGrouped || serverQuery !== "" || Object.keys(timelineConditions ?? {}).length > 0)
      ? `${runId}|timeline|${JSON.stringify([timelineConditions ?? null, serverQuery, timelineGrouped])}|${timelineLocateTarget}`
      : null;
  // biome-ignore lint/correctness/useExhaustiveDependencies: the query is identified by timelineLocateKey
  useEffect(() => {
    if (!timelineLocateKey || timelineLocateTarget === null || restoredRow.current || !runId) return;
    if (located?.key === timelineLocateKey) return;
    const controller = new AbortController();
    locateTimelineRow(
      runId,
      timelineLocateTarget,
      timelineConditions,
      { q: serverQuery, group: timelineGrouped },
      controller.signal,
    )
      .then((position) => {
        if (!controller.signal.aborted) setLocated({ key: timelineLocateKey, position });
      })
      .catch(() => {
        if (!controller.signal.aborted) setLocated({ key: timelineLocateKey, position: null });
      });
    return () => controller.abort();
  }, [timelineLocateKey, located]);
  const activeLocateKey = locateKey ?? timelineLocateKey;

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
    if (activeLocateKey) {
      if (located?.key !== activeLocateKey) return; // waiting for the server position
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
    // A grouped timeline row stands for its members: the linked event may be one of them.
    const members = Array.isArray(row?.fields.groupMembers) ? (row?.fields.groupMembers as unknown[]) : [];
    if (row && row.ref.locator !== target.locator && !members.includes(indexFromRef(target))) {
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
    activeLocateKey,
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
      setSortHold(null);
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
    // A row checkbox keeps focus after a click: Esc still clears the selection from there.
    const onRowCheckbox = target.matches('[data-index] input[type="checkbox"]');
    if (target.closest("input, button, select, textarea") && !(onRowCheckbox && event.key === "Escape"))
      return;
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
    setSortHold(null);
    userNavigated.current = true;
    setFocusIdx(index);
    publishNow(row);
    // Checked rows (the selection) are only changed on purpose: Shift adds the range from the
    // anchor, Ctrl/Cmd toggles this row; a plain click moves the focused row and keeps the ticks.
    if (event.shiftKey && anchorRef.current !== null) {
      setSelectionKeys([...new Set([...selectedKeys, ...rangeKeys(anchorRef.current, index)])]);
    } else if (event.ctrlKey || event.metaKey) {
      toggleAt(index);
    } else {
      anchorRef.current = index;
    }
  };

  const onContextMenu = (event: ReactMouseEvent<HTMLDivElement>) => {
    const rowEl = (event.target as HTMLElement).closest<HTMLElement>("[data-index]");
    if (!rowEl) return;
    event.preventDefault();
    const index = Number(rowEl.dataset.index);
    const row = getDisplayRow(index);
    if (!row) return;
    setSortHold(null);
    userNavigated.current = true;
    setFocusIdx(index);
    // The menu acts on the selection when it holds this row, else on this row alone
    // (gridCommands.menuRows): opening it never clears the checked rows.
    if (!selectedKeys.has(row.rowKey)) anchorRef.current = index;
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
    setSortHold(null);
    setFocusIdx(index);
    setMenuRow(index);
    const rect = target.getBoundingClientRect();
    setMenuAnchor({ x: rect.left, y: rect.bottom });
  }, []);

  const onToggleCheckbox = useCallback(
    (index: number, checked: boolean, range: boolean) => {
      if (range && anchorRef.current !== null) {
        const keys = rangeKeys(anchorRef.current, index);
        const next = new Set(selectedKeys);
        for (const key of keys) {
          if (checked) next.add(key);
          else next.delete(key);
        }
        anchorRef.current = index;
        setSelectionKeys([...next]);
        return;
      }
      toggleAt(index, checked);
    },
    [toggleAt, rangeKeys, selectedKeys, setSelectionKeys],
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
  // Rows on screen: the filtered/sorted rows (compact mode) or every loaded page.
  const displayKeys = useMemo(
    () => (compactMode ? new Set(displayRows.map((r) => r.rowKey)) : null),
    [compactMode, displayRows],
  );
  const batch = batchBarState(
    selectedKeys,
    (key) => (displayKeys ? displayKeys.has(key) : rowsByKey.has(key)),
    tagPromptOpen,
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
    getExportColumns: () => specs,
    getSelectedCount: () => selectedKeys.size,
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

  /** The server sorts this column over the whole collection (else: the loaded rows, with a banner). */
  const serverSortable = (spec: ColumnSpec): boolean =>
    Boolean(spec.sortKey) &&
    (filesGrid ? FILES_SERVER_SORT_KEYS.has(spec.sortKey as string) : Boolean(artifactKind) && serverSorted);
  const sortOf = (spec: ColumnSpec): "ascending" | "descending" | "none" => {
    if (routeSort && serverSortable(spec)) {
      if (spec.sortKey !== routeSort.key) return "none";
      return routeSort.order === "desc" ? "descending" : "ascending";
    }
    const s = sorting.find((item) => item.id === spec.id);
    return s ? (s.desc ? "descending" : "ascending") : "none";
  };
  // Every column sorts (plan r7 §3.2 L2): the indexed ones on the server, the others over the
  // loaded rows under the CLIENT_SCOPE_BANNER — no disabled headers any more.
  const sortReason = (_spec: ColumnSpec): string | null => null;
  const sortTitle = (spec: ColumnSpec): string | undefined =>
    def.source === "paged" && !serverSortable(spec) ? CLIENT_SORT_HINT : undefined;
  const cycleSort = (spec: ColumnSpec) => {
    const current = sortOf(spec);
    // Sorting never moves focus, the selection or the viewer (C-D2): hold the focused row.
    if (focusedRow) setSortHold(focusedRow.rowKey);
    if (serverSortable(spec) && spec.sortKey) {
      setSorting([]);
      setSortNotice(null);
      setSort(
        current === "none"
          ? { key: spec.sortKey, order: "asc" }
          : current === "ascending"
            ? { key: spec.sortKey, order: "desc" }
            : undefined,
      );
      scrollRef.current?.scrollTo?.({ top: 0 });
      return;
    }
    if (routeSort) setSort(undefined);
    const id = spec.id;
    setSorting(
      current === "none" ? [{ id, desc: false }] : current === "ascending" ? [{ id, desc: true }] : [],
    );
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
            ? `정렬: ${sortedSpec?.header ?? routeSort.key} ${routeSort.order === "desc" ? "내림차순" : "오름차순"} (전체 ${
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
  // "→ 실행" only where an NTFS-meta analysis can run: an image input (C-D12).
  const hintsActive = ref.id === "files" && !cq.isLoading && ntfsJoin === null && inputIsImage;
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

  // Range honesty (plan r7 §3.2 L2, 구조 D2): a paged grid always says how many of the server's
  // rows are loaded, and — while a sort / filter runs over the loaded rows only — says that too.
  const pagedGrid = def.source === "paged" && ref.id !== "search";
  const allLoaded = cq.serverTotal !== null && cq.loadedCount >= cq.serverTotal;
  const clientScoped = clientSorting || needle !== "" || cq.clientColumnFilters || cq.clientFiltering;
  const scopeBanner = pagedGrid && clientScoped && !allLoaded && !cq.isLoading;
  const scopeBadge =
    pagedGrid && runId && cq.serverTotal !== null ? (
      <span
        className="grid-scope-badge"
        data-testid="grid-scope-badge"
        title={`서버의 ${formatCount(cq.serverTotal)}행 중 ${formatCount(cq.loadedCount)}행을 불러왔습니다`}
      >
        불러온 {formatCount(cq.loadedCount)} / 전체 {formatCount(cq.serverTotal)}
      </span>
    ) : null;

  const emptyState: GridEmptyState = !runId
    ? {
        icon: "folder",
        text: "케이스를 먼저 선택하세요.",
        action: { command: "case.switch", label: "케이스 열기" },
      }
    : ref.id === "intake"
      ? { icon: "inbox", text: "접수 요약은 그리드가 아닌 요약 화면에서 확인합니다." }
      : ref.id === "search" && !(route.search && route.search.keywords.length > 0)
        ? { icon: "search", text: "검색어를 입력하면 결과가 여기에 표시됩니다." }
        : sortBuilding
          ? { icon: "clock", text: "전체 정렬 인덱스를 만드는 중입니다. 끝나면 정렬된 순서로 표시합니다." }
          : serverQuery
            ? { icon: "search", text: "검색어에 맞는 이벤트가 없습니다. (서버 검색: 전체 이벤트)" }
            : filesGrid && q.trim()
              ? { icon: "search", text: "검색어가 이름·경로에 맞는 파일이 없습니다. (서버 검색: 전체 파일)" }
              : compactMode && needle
                ? { icon: "filter", text: "조건에 맞는 행이 없습니다. 불러온 행 안에서만 필터합니다." }
                : isAnalysis && ref.kind
                  ? {
                      icon: "inbox",
                      text: "이 노드에는 결과가 없습니다.",
                      action: { command: runCommandId(ref.kind), label: "분석 실행" },
                    }
                  : compactMode
                    ? { icon: "filter", text: "조건에 맞는 행이 없습니다. 불러온 행 안에서만 필터합니다." }
                    : { icon: "inbox", text: "이 노드에는 표시할 행이 없습니다." };

  const serverFiltering =
    cq.serverColumnFilters ||
    storeTypes.length > 0 ||
    Boolean(storePath) ||
    Boolean(serverPathFilter(q)) ||
    serverQuery !== "";
  const loadingMessage = serverFiltering
    ? "서버에서 조건에 맞는 행을 찾는 중입니다 … (큰 유형은 수 초 걸릴 수 있습니다)"
    : "목록을 불러오는 중입니다 …";

  // Stage toolbar (visual-polish S2): 검토 = review status + tag, 보고 = output kind; 탐색 = filter popover.
  const toolbarVariant: FilterBarVariant =
    ref.id === "review" ? "review" : ref.id === "outputs" ? "report" : "explore";
  // 종류 choices come from the UNFILTERED rows (useCollectionQuery → filter store typeOptions):
  // picking one kind must not make the others disappear from the menu (review B2-4).
  const typeOptions = useFilterStore((s) => s.typeOptions);
  const kindOptions = useMemo(
    () => (ref.id === "outputs" ? [...typeOptions].sort((a, b) => a.localeCompare(b, "ko")) : undefined),
    [ref.id, typeOptions],
  );

  // 특이사항 notices (U-F4): a flag filter on a run without a flag set says so (never an empty
  // grid without a reason); policy-dependent sources with no records read "부재 ≠ 미발생".
  const routeFlagsActive = useFilterStore((s) => Boolean(s.filters.flags?.length || s.filters.flagGrade));
  const flagNotices = useMemo(() => {
    const out: Array<{ id: string; text: string }> = [];
    if (ref.id !== "artifacts" || !runTree.data) return out;
    const unavailable = flagsUnavailableReason(runTree.data);
    if (routeFlagsActive && unavailable) out.push({ id: "missing", text: unavailable });
    // A partial flag set (some sources unreadable / corrupt flags skipped): say so on every
    // artifact grid, filtered or not — an empty 특이사항 cell may mean "not read".
    const partial = flagsPartialNotice(runTree.data);
    if (partial) out.push({ id: "partial", text: partial });
    if (routeFlagsActive || ref.kind === "eventlog") {
      for (const absent of policyAbsences(runTree.data)) {
        out.push({ id: `policy-${absent.id}`, text: `${absent.label}: ${absent.note}` });
      }
    }
    return out;
  }, [ref.id, ref.kind, runTree.data, routeFlagsActive]);

  // 채널 chip labels: the run's `/tree` channel groups (Korean labels of core/eventlog_channels.py).
  const channelGroupLabels = useMemo(() => {
    const groups = mergedKindNode(runTree.data, "eventlog")?.channel_groups;
    return groups?.length ? Object.fromEntries(groups.map((group) => [group.id, group.label])) : undefined;
  }, [runTree.data]);

  // 열 설정 overflow at the end of the 조건 줄 (U-F1): 열 선택 (+ catalogue auxiliary columns,
  // record fields) and the column-filter row; 열 구성 / 밀도 live in the 조건 panel.
  const auxIds = family ? auxColumnIds(family).filter((id) => columns.some((c) => c.id === id)) : [];
  const columnMenu = (
    <ColumnMenu
      preset={preset}
      columns={columns}
      visibility={visibility}
      onToggleColumn={toggleColumn}
      autoHidden={autoHidden}
      collectionLabel={def.label}
      auxColumns={
        family && auxIds.length
          ? {
              family: family.label,
              ids: auxIds,
              onToggleAll: (on) => {
                for (const id of auxIds) toggleColumn(id, on);
                announce(
                  on
                    ? `보조 열 ${auxIds.length}개를 추가했습니다.`
                    : `보조 열 ${auxIds.length}개를 뺐습니다.`,
                );
              },
            }
          : undefined
      }
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
  );
  const choosePreset = (next: GridPreset) => {
    setPreset(next);
    try {
      window.localStorage.setItem("rapidtriage.grid.preset", next);
    } catch {
      // Preset simply does not persist.
    }
  };

  return (
    <section
      className="grid-root"
      aria-label={`${def.label} 그리드`}
      data-density={density}
      data-preset={preset}
      data-batch={batch.visible ? "" : undefined}
      // Room under the last row: 52px for the one-line bar (review #2), more while an editor is open.
      style={
        batch.visible && batchHeight > 0
          ? ({ "--batch-reserve": `${Math.max(52, batchHeight + 14)}px` } as CSSProperties)
          : undefined
      }
    >
      <GridToolbar
        filterRef={filterRef}
        query={q}
        onQuery={route.setQuery}
        onReturnToGrid={returnToGrid}
        variant={toolbarVariant}
        reviewStatus={ref.id === "review" ? ref.status : undefined}
        onReviewStatus={(status) => route.navigate({ id: "review", ...(status ? { status } : {}) }, q)}
        kindOptions={kindOptions}
        display={{ preset, onPreset: choosePreset, density, onDensity: setDensity }}
        resultCount={runId ? { count: cq.isLoading ? null : resultCount, loading: cq.isLoading } : undefined}
        trailing={columnMenu}
        channelGroupLabels={channelGroupLabels}
        extra={
          ref.id === "docs" || scopeBadge ? (
            <>
              {ref.id === "docs" ? (
                <DocsMatchedToggle
                  on={ref.category === DOCS_MATCHED}
                  onChange={(on) =>
                    route.navigate({ id: "docs", ...(on ? { category: DOCS_MATCHED } : {}) }, q)
                  }
                />
              ) : null}
              {scopeBadge}
            </>
          ) : undefined
        }
      />

      {serverSorted ? (
        <p className="grid-sortstatus" data-testid="grid-sort-status" hidden={!sortStatusText}>
          {sortStatusText}
        </p>
      ) : null}

      {serverSearch && cq.pageMeta?.timeline_legacy === true ? (
        <p className="flag-grid-notice" role="note" data-testid="grid-timeline-legacy">
          {TIMELINE_LEGACY_HINT}
        </p>
      ) : null}

      {serverSearch ? (
        <p className="grid-sortstatus" data-testid="grid-group-status">
          {timelineGrouped
            ? "같은 대상·같은 초·같은 시각 종류의 이벤트는 한 행으로 묶어 출처 수로 표시합니다."
            : "이벤트를 하나씩 표시합니다(묶지 않음)."}{" "}
          <button
            type="button"
            className="grid-btn grid-btn-quiet"
            data-testid="grid-group-toggle"
            aria-pressed={timelineGrouped}
            onClick={() => setTimelineGrouped((on) => !on)}
          >
            {timelineGrouped ? "묶지 않고 보기" : "출처 묶어 보기"}
          </button>
        </p>
      ) : null}

      {scopeBanner ? (
        <p className="grid-scope-banner" role="note" data-testid="grid-scope-banner">
          <strong>{CLIENT_SCOPE_BANNER}</strong> — 불러온 {formatCount(cq.loadedCount)}행
          {cq.serverTotal !== null ? ` / 전체 ${formatCount(cq.serverTotal)}행` : ""}에서만 정렬·필터했습니다.
          {filesGrid ? " 전체 정렬: 이름·경로·크기·수정·NTFS 생성·특이사항 열." : ""}
          {cq.canLoadMore ? (
            <button type="button" className="grid-btn grid-btn-quiet" onClick={loadMore}>
              더 불러오기
            </button>
          ) : null}
        </p>
      ) : null}

      {statusLines.map((line) => (
        <p key={line.id} className="grid-sortstatus" data-testid={`grid-${line.id}-status`}>
          {line.text}
        </p>
      ))}

      {flagNotices.map((notice) => (
        <p key={notice.id} className="flag-grid-notice" role="note" data-testid={`grid-flag-${notice.id}`}>
          {notice.text}
        </p>
      ))}

      {cq.error && displayCount > 0 ? (
        <div className="grid-error" role="alert">
          <span>목록을 불러오지 못했습니다. {cq.error.message}</span>
          <button type="button" className="grid-btn" onClick={cq.refetch}>
            다시 시도
          </button>
        </div>
      ) : null}

      <div className="grid-frame">
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
            scrollPaddingTop: HEADER_HEIGHT + (filterRowShown ? rowHeight + 4 : 0),
          }}
          onKeyDown={onKeyDown}
          onMouseDown={onRowMouseDown}
          onContextMenu={onContextMenu}
        >
          <div className="grid-inner" style={{ width: totalWidth }}>
            <div role="rowgroup" className="grid-head">
              <div
                role="row"
                aria-rowindex={1}
                className="grid-row grid-header"
                style={{ height: HEADER_HEIGHT }}
              >
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
                  const noValues = !hint && keptEmptyIds.has(spec.id);
                  const noValuesId = `${hintPrefix}-novalue-${spec.id}`;
                  const describedBy =
                    [
                      spec.sortHint ? `${hintPrefix}-${spec.id}` : "",
                      hint ? hintId : "",
                      noValues ? noValuesId : "",
                    ]
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
                          // The full header is always the tooltip (a narrow column truncates it, U-F8).
                          title={
                            reason
                              ? undefined
                              : (spec.sortHint ?? hint?.text ?? sortTitle(spec) ?? spec.header)
                          }
                          onClick={() => cycleSort(spec)}
                        >
                          {spec.header}
                          <span aria-hidden="true" className="grid-sort-mark">
                            {sort === "ascending" ? (
                              <Icon name="chevron-up" />
                            ) : sort === "descending" ? (
                              <Icon name="chevron-down" />
                            ) : null}
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
                      {noValues ? (
                        <span
                          id={noValuesId}
                          className="grid-hcell-novalue"
                          title={KEPT_EMPTY_COLUMN_NOTE}
                          data-testid={`grid-novalue-${spec.id}`}
                        >
                          {KEPT_EMPTY_COLUMN_NOTE}
                        </span>
                      ) : null}
                      <div
                        aria-hidden="true"
                        className="grid-resizer"
                        onMouseDown={
                          column.getCanResize()
                            ? (e) => {
                                e.stopPropagation();
                                const start = e.clientX;
                                const startSize = widths[i] ?? column.getSize();
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
                    focused={item.index === clampedFocus && (sortHold === null || row?.rowKey === sortHold)}
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
          {/* One state at a time (review #11): the error card replaces the empty state. */}
          {displayCount === 0 && !cq.isLoading && !cq.error ? (
            <GridEmpty state={emptyState} testId="grid-empty" />
          ) : null}
          {displayCount === 0 && cq.isLoading && runId ? (
            // A typed / server-filtered page can scan for seconds: never a blank grid meanwhile —
            // eight skeleton rows under the header; the sentence goes to the footer.
            <div className="grid-skeleton-rows" data-testid="grid-loading" aria-hidden="true">
              {SKELETON_ROWS.map((n) => (
                <div key={n} className="grid-skeleton-row">
                  <span className="grid-skeleton" style={{ width: "60%" }} />
                  <span className="grid-skeleton" style={{ width: "30%" }} />
                  <span className="grid-skeleton" style={{ width: "45%" }} />
                </div>
              ))}
            </div>
          ) : null}
          {cq.error && displayCount === 0 ? (
            <div className="grid-error-card" role="alert">
              <span className="grid-empty-icon" aria-hidden="true">
                <Icon name="alert" />
              </span>
              <p className="grid-empty-text">목록을 불러오지 못했습니다. {cq.error.message}</p>
              <button type="button" className="button" onClick={cq.refetch}>
                다시 시도
              </button>
            </div>
          ) : null}
        </div>
        {/* The batch bar floats over the bottom of the grid: selecting never moves the rows. */}
        <BatchBar
          selectedCount={batch.count}
          visible={batch.visible}
          context={context}
          onDisabled={(reason) => toast.show(reason, "info")}
          onClear={() => setSelectionKeys([])}
          onTag={(tag) => void runBatch(host, "tag", tag)}
          tagPromptOpen={tagPromptOpen}
          onTagPromptChange={setTagPromptOpen}
          onNote={runId ? (note) => void runNote(host, note) : undefined}
          onHeight={setBatchHeight}
        />
      </div>

      <GridFooter
        selectedCount={selectedKeys.size}
        page={currentPage}
        pageCount={cq.pageCount}
        total={cq.total}
        shown={displayCount}
        backend={cq.backend}
        elapsedMs={cq.elapsedMs}
        truncated={cq.truncated}
        filtering={needle !== "" || serverQuery !== ""}
        serverSearch={serverQuery !== ""}
        sorting={clientSorting}
        loadedCount={cq.loadedCount}
        canLoadMore={compactMode && cq.canLoadMore}
        serverPathFilter={ref.id === "artifacts" ? serverPathFilter(q) : undefined}
        scanned={cq.scanned}
        onLoadMore={loadMore}
        loading={cq.isFetching}
        loadingText={displayCount === 0 && cq.isLoading ? loadingMessage : undefined}
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
    </section>
  );
}
