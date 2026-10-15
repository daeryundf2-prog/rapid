import type { GridRow } from "../../contracts/collection";
import type { RowRef } from "../../contracts/rowRef";
import { flatValue, isScalarish } from "../../utils/flatValue";
import type { CellValue, ColumnSpec } from "./types";

/** Null/empty last; numbers numerically; strings with Korean-aware numeric collation. */
export function compareValues(a: CellValue, b: CellValue): number {
  const aEmpty = a === null || a === undefined || a === "";
  const bEmpty = b === null || b === undefined || b === "";
  if (aEmpty && bEmpty) return 0;
  if (aEmpty) return 1;
  if (bEmpty) return -1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b), "ko", { numeric: true, sensitivity: "base" });
}

export function displayText(spec: ColumnSpec, row: GridRow): string {
  if (spec.format) return spec.format(row);
  const value = spec.value(row);
  return value === null || value === undefined ? "" : String(value);
}

const haystacks = new WeakMap<GridRow, string>();

/** Lower-cased searchable text of a row (title, path, tags, provider, type and every string field). */
export function rowHaystack(row: GridRow): string {
  const cached = haystacks.get(row);
  if (cached !== undefined) return cached;
  const parts: string[] = [
    row.title,
    row.sourcePath ?? "",
    row.artifactType ?? "",
    row.provider ?? "",
    row.tags.join(" "),
  ];
  for (const value of Object.values(row.fields)) {
    if (typeof value === "string" || typeof value === "number") parts.push(String(value));
  }
  // Decoded artifact fields: the full (never clipped) text of every scalar / scalar-list value.
  const details = row.fields.details;
  if (typeof details === "object" && details !== null && !Array.isArray(details)) {
    for (const value of Object.values(details)) {
      if (isScalarish(value)) parts.push(flatValue(value));
    }
  }
  const text = parts.join("\n").toLowerCase();
  haystacks.set(row, text);
  return text;
}

export function matchesFilter(row: GridRow, needle: string): boolean {
  if (!needle) return true;
  const haystack = rowHaystack(row);
  return needle
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((term) => haystack.includes(term));
}

export function backendLabel(backend: string): string {
  switch (backend) {
    case "fts":
      return "FTS";
    case "scan":
      return "스캔";
    case "file":
      return "파일";
    case "case":
      return "케이스";
    default:
      return backend;
  }
}

export function formatCount(n: number): string {
  return n.toLocaleString("ko-KR");
}

/** The one aria-live sentence: "{n}건 · {backend} · {ms}ms". */
export function resultSentence(count: number, backend: string, elapsedMs: number): string {
  return `${formatCount(count)}건 · ${backendLabel(backend) || "-"} · ${Math.round(elapsedMs)}ms`;
}

/**
 * Global row index encoded in an API locator ("/candidates/894" -> 894), so a
 * URL `row=` can be resolved to a server page. Null when the locator carries none.
 */
export function indexFromRef(ref: RowRef): number | null {
  if (!["files", "docs", "timeline", "indicators", "artifacts", "analysis"].includes(ref.collection))
    return null;
  if ((ref.collection === "artifacts" || ref.collection === "analysis") && !ref.kind) return null;
  const match = /\/(\d+)$/.exec(ref.locator);
  return match?.[1] ? Number(match[1]) : null;
}

/** Artifacts text filter that the server can apply (`path_contains`): one token, no spaces. */
export function serverPathFilter(text: string | undefined): string | undefined {
  const t = text?.trim();
  return t && !/\s/.test(t) ? t : undefined;
}

/**
 * Fit column widths to the visible grid width: slack goes to the flexing column (항목/이름).
 * Columns are never shrunk here — a narrow pane hides low-priority default columns instead
 * (`priorityHiddenColumns`), and whatever is still too wide scrolls sideways. `grow` < 0 (the
 * user resized 항목) or `available` ≤ 0 (not measured yet) leaves the widths unchanged.
 */
export function fitColumnWidths(
  widths: readonly number[],
  options: { grow: number; available: number },
): number[] {
  const out = [...widths];
  const { grow, available } = options;
  if (!(available > 0) || out.length === 0) return out;
  const total = out.reduce((sum, w) => sum + w, 0);
  if (total < available && grow >= 0 && grow < out.length) out[grow] = (out[grow] ?? 0) + (available - total);
  return out;
}

/** Why a default column is off screen although its preset shows it. */
export type AutoHideReason = "width" | "empty";

/** 열 menu hint per reason ("폭 부족으로 숨김 — 표시"). */
export const AUTO_HIDE_LABEL: Record<AutoHideReason, string> = {
  width: "폭 부족으로 숨김",
  empty: "값이 없어 숨김",
};

/**
 * Responsive default columns: ids to hide, lowest priority first, while the visible columns'
 * minimum widths exceed `available`. `columns` are the visible columns with the width each needs;
 * ids missing from `priority` (promoted / user-added columns), ids in `keep` (shown explicitly by
 * the user) and the first priority id (항목/이름) are never hidden. `available` ≤ 0 (not measured
 * yet) hides nothing.
 */
export function priorityHiddenColumns(
  columns: readonly { id: string; min: number }[],
  options: { priority: readonly string[]; available: number; keep?: ReadonlySet<string> },
): string[] {
  const { priority, available, keep } = options;
  if (!(available > 0)) return [];
  const present = new Map(columns.map((c) => [c.id, c.min]));
  let total = columns.reduce((sum, c) => sum + c.min, 0);
  const hidden: string[] = [];
  for (let i = priority.length - 1; i >= 1 && total > available; i--) {
    const id = priority[i] as string;
    const min = present.get(id);
    if (min === undefined || keep?.has(id)) continue;
    hidden.push(id);
    total -= min;
  }
  return hidden;
}

/** A cell value that shows nothing (null, "", whitespace, an empty list). */
function isEmptyValue(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (typeof value === "string") return value.trim() === "";
  if (Array.isArray(value)) return value.length === 0;
  return false;
}

/**
 * Default columns with no value in any loaded row (review #9; generalises "시각 goes when no
 * row has a time"): ids among `candidates` whose every loaded row is empty — never the ones in
 * `keep` (shown by the user), never a column with an empty-state hint (its header explains the
 * blank, e.g. NTFS 생성 → 실행), and nothing at all before a row has loaded.
 */
export function emptyColumnIds(
  columns: readonly ColumnSpec[],
  rows: readonly GridRow[],
  options: { candidates: readonly string[]; keep?: ReadonlySet<string> },
): string[] {
  if (rows.length === 0) return [];
  const wanted = new Set(options.candidates);
  return columns
    .filter((c) => wanted.has(c.id) && !options.keep?.has(c.id) && !c.emptyHint)
    .filter((c) => rows.every((row) => isEmptyValue(c.value(row)) && displayText(c, row).trim() === ""))
    .map((c) => c.id);
}
