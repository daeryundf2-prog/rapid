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
    // No engine ("none"): nothing to name (R7 L3 — never the raw token).
    case "none":
    case "":
      return "";
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
 * A narrow pane first hides low-priority default columns (`priorityHiddenColumns`, which counts
 * each column at its minimum); with `mins` the columns still wider than the pane then shrink
 * toward those minimums (fixed-width columns first, then the long-text ones, each by its room
 * above the minimum), so a layout whose minimums fit never scrolls sideways (the browser kind
 * at 1920, r7 S1). Without `mins` the widths stay; when even the minimums do not fit, every
 * column sits at its minimum and the grid scrolls. `grow` < 0 (the user resized 항목)
 * or `available` ≤ 0 (not measured yet) leaves the widths unchanged.
 */
export function fitColumnWidths(
  widths: readonly number[],
  options: { grow: number; available: number; weights?: readonly number[]; mins?: readonly number[] },
): number[] {
  const out = [...widths];
  const { grow, available, weights, mins } = options;
  if (!(available > 0) || out.length === 0) return out;
  const total = out.reduce((sum, w) => sum + w, 0);
  if (total > available && mins) return shrinkToFit(out, mins, total - available, weights);
  if (total >= available) return out;
  const slack = available - total;
  // Weighted growth (C-D7): the spare width goes to the long-text columns (항목 · 경로 · URL …)
  // by weight; the rounding remainder goes to the heaviest one.
  const weightSum = weights ? weights.reduce((sum, w) => sum + Math.max(0, w), 0) : 0;
  if (weights && weightSum > 0) {
    let given = 0;
    let heaviest = -1;
    weights.forEach((w, i) => {
      if (i >= out.length || !(w > 0)) return;
      const share = Math.floor((slack * w) / weightSum);
      out[i] = (out[i] ?? 0) + share;
      given += share;
      if (heaviest < 0 || w > (weights[heaviest] ?? 0)) heaviest = i;
    });
    if (heaviest >= 0) out[heaviest] = (out[heaviest] ?? 0) + (slack - given);
    return out;
  }
  if (grow >= 0 && grow < out.length) out[grow] = (out[grow] ?? 0) + slack;
  return out;
}

/** Take up to `excess` px off the `eligible` columns, by their room above `mins`; returns what it took. */
function shrinkBy(
  widths: number[],
  mins: readonly number[],
  excess: number,
  eligible: (i: number) => boolean,
): number {
  const room = widths.map((w, i) => (eligible(i) ? Math.max(0, w - Math.min(w, mins[i] ?? w)) : 0));
  const totalRoom = room.reduce((sum, r) => sum + r, 0);
  if (totalRoom <= 0 || excess <= 0) return 0;
  if (totalRoom <= excess) {
    room.forEach((r, i) => {
      widths[i] = (widths[i] ?? 0) - r;
    });
    return totalRoom;
  }
  let taken = 0;
  let roomiest = 0;
  room.forEach((r, i) => {
    if (r > (room[roomiest] ?? 0)) roomiest = i;
    const cut = Math.floor((excess * r) / totalRoom);
    widths[i] = (widths[i] ?? 0) - cut;
    taken += cut;
  });
  // The rounding remainder comes off the column with the most room (it has at least that much).
  widths[roomiest] = (widths[roomiest] ?? 0) - (excess - taken);
  return excess;
}

/**
 * Take `excess` px off the columns above their minimum: the fixed-width columns (time, number,
 * chips — weight 0) first, the long-text ones (항목 · URL · 제목 …) only for what is left, so the
 * text keeps its width the longest. Everything at minimum when even that is short.
 */
function shrinkToFit(
  widths: number[],
  mins: readonly number[],
  excess: number,
  weights: readonly number[] | undefined,
): number[] {
  const out = [...widths];
  const taken = shrinkBy(out, mins, excess, (i) => !((weights?.[i] ?? 0) > 0));
  shrinkBy(out, mins, excess - taken, () => true);
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
  options: {
    candidates: readonly string[];
    keep?: ReadonlySet<string>;
    /** The empty-state hints do not apply (files of a folder input: no NTFS-meta to run, C-D12). */
    ignoreHints?: boolean;
  },
): string[] {
  if (rows.length === 0) return [];
  const wanted = new Set(options.candidates);
  return columns
    .filter((c) => wanted.has(c.id) && !options.keep?.has(c.id) && (options.ignoreHints || !c.emptyHint))
    .filter((c) => rows.every((row) => isEmptyValue(c.value(row)) && displayText(c, row).trim() === ""))
    .map((c) => c.id);
}
