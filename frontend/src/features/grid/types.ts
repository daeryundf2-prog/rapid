import type { ReactNode } from "react";
import type { RawPage, RawRow } from "../../api/collections";
import type { CollectionId, CollectionRef, ColumnFilter, GridRow } from "../../contracts/collection";

export type GridPreset = "analysis" | "compact" | "source" | "axiom";

export const PRESET_LABELS: Record<GridPreset, string> = {
  analysis: "분석 기본",
  compact: "압축",
  source: "출처 중심",
  axiom: "AXIOM 스타일",
};

/** The preset a grid starts with (조건 줄 chips show any other one). */
export const DEFAULT_PRESET: GridPreset = "analysis";

export type Density = "compact" | "default" | "comfortable";

/** Row height in px per density token (plan 4.5: 24/28/32). */
export const DENSITY_ROW_HEIGHT: Record<Density, number> = { compact: 24, default: 28, comfortable: 32 };

export const DENSITY_LABELS: Record<Density, string> = {
  compact: "촘촘하게",
  default: "기본",
  comfortable: "여유 있게",
};

export type CellValue = string | number | boolean | null | undefined;

export interface ColumnSpec {
  id: string;
  /** Korean header. */
  header: string;
  /** Default width in px (resizable). */
  width: number;
  minWidth?: number;
  align?: "right";
  mono?: boolean;
  /** Presets in which the column is visible by default. */
  presets: GridPreset[];
  /** Raw value used for sorting and the client text filter. */
  value: (row: GridRow) => CellValue;
  /** Display text; defaults to String(value). Also the cell tooltip and the copy/filter text. */
  format?: (row: GridRow) => string;
  /** Cell tooltip when it should differ from the display text (e.g. the raw value behind a label). */
  tooltip?: (row: GridRow) => string;
  /** Rich cell content (chips, icons); falls back to the display text when absent. */
  render?: (row: GridRow) => ReactNode;
  /**
   * Server sort key (artifacts: `timestamp` | `details.<key>`). Only columns that read a
   * single server-sortable value have one; artifact headers without it are disabled with a reason.
   */
  sortKey?: string;
  /**
   * Accessible name / tooltip of the sort button when the column shows one of several keys but the
   * server sorts on one of them, e.g. "실행 파일 정렬 (executable_hint 기준)".
   */
  sortHint?: string;
  /** Header reason when the column has no sortKey for a specific cause (e.g. list values). */
  unsortableReason?: string;
  /**
   * The column shows the first of these details keys that is present; the grid sorts on the first one
   * present in the loaded rows (with `sortHintFor(key)`), so the sorted key is the displayed key.
   */
  sortCandidates?: string[];
  /** Hint for the candidate the grid picked (see `sortCandidates`). */
  sortHintFor?: (key: string) => string;
  /** `details` keys this column already shows (left out of the "레코드 필드 추가" list). */
  fieldKeys?: string[];
  /**
   * Column header filter input (plan analysis-workbench-p1 §4): "text" = contains, "time" =
   * from/to, "number" = min/max, "none" = no input. Default: `timestamp` → time, right-aligned → number.
   */
  filterKind?: "text" | "time" | "number" | "none";
  /**
   * The column is filled by an analysis job that has not run yet (e.g. files NTFS columns):
   * the header says so and links to the job's run command.
   */
  emptyHint?: { text: string; command: string; commandLabel: string };
}

export interface MapContext {
  ref: CollectionRef;
  /** The raw page the row came from (page-level facts such as files `ntfs_join`). */
  page?: RawPage;
}

/**
 * What else picks a grid's columns (analysis rows, R3 §3.3): the route's column filters (an
 * ntfs-meta `f:source` sub-view) and the loaded rows' artifact types (one catalogue family).
 */
export interface ColumnsContext {
  columnFilters?: readonly ColumnFilter[];
  rowTypes?: readonly string[];
}

export interface CollectionDef {
  id: CollectionId;
  /** Korean label for headings and the empty state. */
  label: string;
  columns: ColumnSpec[];
  /** Kind-aware column set (e.g. eventlog adds 이벤트ID/채널/메시지); defaults to `columns`. */
  /** Columns of one kind; `types` = the grid's 유형 filter (artifact type families pick their own set). */
  columnsFor?: (ref: CollectionRef, types?: readonly string[], context?: ColumnsContext) => ColumnSpec[];
  /**
   * Responsive default layout: the column ids in priority order (highest first) for the default
   * ("분석 기본") preset. While the columns' minimum widths (`minWidth`) exceed the grid width the
   * lowest-priority ones are hidden (열 menu: "폭 부족으로 숨김 — 표시"). Undefined = no hiding.
   */
  widthPriority?: (ref: CollectionRef, types?: readonly string[]) => readonly string[] | undefined;
  /** Map one raw API row to the normalised GridRow. `index` is the global row index. */
  mapRow: (raw: RawRow, index: number, ctx: MapContext) => GridRow;
  /** "paged" = server offset/limit; "whole" = one response, paged on the client. */
  source: "paged" | "whole";
  /** Fetch one window (paged) or the whole collection (whole; offset 0). */
  fetch: (
    runId: string,
    query: import("../../contracts/collection").CollectionQuery,
    signal?: AbortSignal,
  ) => Promise<RawPage>;
  /**
   * Server-sorted collections: sorted position of one record (`locate=`), for `row=` deep links.
   * Defined by collections whose rows' locator index is a server record index.
   */
  locate?: (
    runId: string,
    ref: CollectionRef,
    sort: import("../../contracts/collection").ServerSort,
    recordIndex: number,
    signal?: AbortSignal,
  ) => Promise<{ status: "ready" | "building" | "unsupported"; position: number | null }>;
}
