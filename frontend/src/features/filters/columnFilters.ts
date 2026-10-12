/**
 * Column header filters (plan analysis-workbench-p1 §4, U-P1-4): pure predicates and
 * helpers. The URL grammar (`cf=`) lives in router.ts; which filters the API applies is
 * decided in filterModel.partitionFilters. Everything here runs on loaded rows only.
 *
 *  - text   (`col:foo`)          → the cell's display text contains "foo" (case-insensitive)
 *  - number (`col>10`, `col<20`) → numeric cell value ≥ 10 / ≤ 20 (both may be set)
 *  - time   (`col:a..b`)         → the cell instant lies in [a, b]; either side may be empty;
 *                                  a date-only bound covers the whole (UTC) day
 */

import type { ColumnFilter, GridRow } from "../../contracts/collection";
import { parseInstant } from "../../utils/time";
import { displayText } from "../grid/gridUtils";
import type { ColumnSpec } from "../grid/types";

export type ColumnFilterKind = "text" | "time" | "number" | "none";

export function filterKindOf(spec: Pick<ColumnSpec, "id" | "align" | "filterKind">): ColumnFilterKind {
  if (spec.filterKind) return spec.filterKind;
  if (spec.id === "timestamp") return "time";
  if (spec.align === "right") return "number";
  return "text";
}

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
const DAY_MS = 86_400_000;

/** `a..b` → bounds in ms (null = open side / unparseable). */
export function timeBounds(value: string): { from: number | null; to: number | null; valid: boolean } {
  const [rawFrom = "", rawTo = ""] = value.includes("..") ? value.split("..", 2) : [value, value];
  const from = rawFrom.trim() ? (parseInstant(rawFrom.trim())?.getTime() ?? Number.NaN) : null;
  let to = rawTo.trim() ? (parseInstant(rawTo.trim())?.getTime() ?? Number.NaN) : null;
  if (to !== null && !Number.isNaN(to) && DATE_ONLY.test(rawTo.trim())) to += DAY_MS - 1;
  const valid = !Number.isNaN(from ?? 0) && !Number.isNaN(to ?? 0) && (from !== null || to !== null);
  return { from: valid ? from : null, to: valid ? to : null, valid };
}

export function isValidBound(kind: ColumnFilterKind, op: ColumnFilter["op"], value: string): boolean {
  const v = value.trim();
  if (!v) return true;
  if (kind === "number" && op !== ":") return Number.isFinite(Number(v));
  if (kind === "time") return parseInstant(v) !== null;
  return true;
}

function numericValue(raw: unknown): number | null {
  if (typeof raw === "number") return Number.isFinite(raw) ? raw : null;
  if (typeof raw === "string" && raw.trim() !== "") {
    const text = raw.trim();
    const n = /^0x[0-9a-f]+$/i.test(text) ? Number.parseInt(text, 16) : Number(text);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

/** True when the row passes one column filter of `spec`. */
export function matchesColumnFilter(spec: ColumnSpec, row: GridRow, filter: ColumnFilter): boolean {
  const kind = filterKindOf(spec);
  if (kind === "none") return true;
  if (kind === "number" && filter.op !== ":") {
    const limit = Number(filter.value);
    if (!Number.isFinite(limit)) return true; // malformed bound: ignored (the input shows why)
    const value = numericValue(spec.value(row));
    if (value === null) return false;
    return filter.op === ">" ? value >= limit : value <= limit;
  }
  if (kind === "time" && filter.op === ":" && filter.value.includes("..")) {
    const bounds = timeBounds(filter.value);
    if (!bounds.valid) return true;
    const raw = spec.value(row);
    const at = parseInstant(typeof raw === "number" || typeof raw === "string" ? raw : null)?.getTime();
    if (at === undefined) return false;
    if (bounds.from !== null && at < bounds.from) return false;
    if (bounds.to !== null && at > bounds.to) return false;
    return true;
  }
  const needle = filter.value.toLowerCase();
  if (!needle) return true;
  // 유형(정확히): exact (case-insensitive) artifact type, never a substring.
  if (spec.id === "type") return String(spec.value(row) ?? "").toLowerCase() === needle;
  const shown = displayText(spec, row).toLowerCase();
  if (shown.includes(needle)) return true;
  const raw = spec.value(row);
  return raw !== null && raw !== undefined && String(raw).toLowerCase().includes(needle);
}

/** Rows passing every column filter; filters on unknown columns are ignored. */
export function applyColumnFilters(
  rows: GridRow[],
  filters: readonly ColumnFilter[],
  resolve: (col: string) => ColumnSpec | undefined,
): GridRow[] {
  const active = filters
    .map((filter) => ({ filter, spec: resolve(filter.col) }))
    .filter((entry): entry is { filter: ColumnFilter; spec: ColumnSpec } => entry.spec !== undefined);
  if (active.length === 0) return rows;
  return rows.filter((row) => active.every(({ filter, spec }) => matchesColumnFilter(spec, row, filter)));
}

/** Replace the filters of one column (by op) with `next` (empty values removed). */
export function setColumnFilter(
  filters: readonly ColumnFilter[],
  col: string,
  op: ColumnFilter["op"],
  value: string,
): ColumnFilter[] {
  const rest = filters.filter((f) => !(f.col === col && f.op === op));
  return value.trim() ? [...rest, { col, op, value: value.trim() }] : rest;
}

export function columnFilterValue(
  filters: readonly ColumnFilter[] | undefined,
  col: string,
  op: ColumnFilter["op"],
): string {
  return filters?.find((f) => f.col === col && f.op === op)?.value ?? "";
}

/** `from..to` time filter text from its two inputs (empty when both are empty). */
export function joinTimeRange(from: string, to: string): string {
  const a = from.trim();
  const b = to.trim();
  return a || b ? `${a}..${b}` : "";
}

export function splitTimeRange(value: string): [string, string] {
  if (!value) return ["", ""];
  if (!value.includes("..")) return [value, ""];
  const [from = "", to = ""] = value.split("..", 2);
  return [from, to];
}
