import type { GridRow } from "../../contracts/collection";
import type { RowRef } from "../../contracts/rowRef";
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
  if (!["files", "docs", "timeline", "indicators", "artifacts"].includes(ref.collection)) return null;
  if (ref.collection === "artifacts" && !ref.kind) return null;
  const match = /\/(\d+)$/.exec(ref.locator);
  return match?.[1] ? Number(match[1]) : null;
}

/** Artifacts text filter that the server can apply (`path_contains`): one token, no spaces. */
export function serverPathFilter(text: string | undefined): string | undefined {
  const t = text?.trim();
  return t && !/\s/.test(t) ? t : undefined;
}
