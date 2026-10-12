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
 * Fit column widths to the visible grid width (visual-polish B2 #2): slack goes to the flexing
 * column (항목), overflow is taken from the shrinkable columns (항목 · 경로) down to their minimum,
 * in proportion to the room each has left. Columns the user resized stay as they are
 * (`shrinkable` / `grow` false). `available` ≤ 0 (not measured yet) leaves the widths unchanged.
 */
export function fitColumnWidths(
  widths: readonly number[],
  options: { grow: number; shrinkable: readonly boolean[]; mins: readonly number[]; available: number },
): number[] {
  const out = [...widths];
  const { grow, shrinkable, mins, available } = options;
  if (!(available > 0) || out.length === 0) return out;
  const total = out.reduce((sum, w) => sum + w, 0);
  if (total < available) {
    if (grow >= 0 && grow < out.length) out[grow] = (out[grow] ?? 0) + (available - total);
    return out;
  }
  let excess = total - available;
  const room = out.map((w, i) => (shrinkable[i] ? Math.max(0, w - (mins[i] ?? w)) : 0));
  const totalRoom = room.reduce((sum, r) => sum + r, 0);
  if (totalRoom <= 0 || excess <= 0) return out;
  const take = Math.min(excess, totalRoom);
  for (let i = 0; i < out.length; i++) {
    const r = room[i] ?? 0;
    if (r <= 0) continue;
    const cut = Math.min(r, Math.round((take * r) / totalRoom));
    out[i] = (out[i] ?? 0) - cut;
    excess -= cut;
  }
  return out;
}

/** "C:\a\b\file.json" → ["C:\a\b\", "file.json"]: the head ellipsizes, the file name stays. */
export function splitPathTail(path: string): [string, string] {
  const cut = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  if (cut < 0 || cut === path.length - 1) return ["", path];
  return [path.slice(0, cut + 1), path.slice(cut + 1)];
}
