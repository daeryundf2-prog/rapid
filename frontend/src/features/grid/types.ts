import type { ReactNode } from "react";
import type { RawPage, RawRow } from "../../api/collections";
import type { CollectionId, CollectionRef, GridRow } from "../../contracts/collection";

export type GridPreset = "analysis" | "compact" | "source" | "axiom";

export const PRESET_LABELS: Record<GridPreset, string> = {
  analysis: "분석 기본",
  compact: "압축",
  source: "출처 중심",
  axiom: "AXIOM 스타일",
};

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
  /** Rich cell content (chips, icons); falls back to the display text when absent. */
  render?: (row: GridRow) => ReactNode;
}

export interface MapContext {
  ref: CollectionRef;
}

export interface CollectionDef {
  id: CollectionId;
  /** Korean label for headings and the empty state. */
  label: string;
  columns: ColumnSpec[];
  /** Kind-aware column set (e.g. eventlog adds 이벤트ID/채널/메시지); defaults to `columns`. */
  columnsFor?: (ref: CollectionRef) => ColumnSpec[];
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
}
