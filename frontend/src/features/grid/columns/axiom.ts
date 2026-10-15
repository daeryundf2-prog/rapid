import type { GridRow } from "../../../contracts/collection";
import type { CollectionDef, ColumnSpec } from "../types";
import { baseName, formatBytes, REVIEW_LABELS, str } from "./common";
import { tagStatusCell } from "./StatusCells";

/**
 * "AXIOM style" column preset (X13): two-line first column (title over
 * type + key detail) and a tag/status chip column right after it.
 *
 * The two title lines are one string with a newline (CSS `white-space: pre` +
 * `::first-line`, see filters.css). The chip column renders <StatusChip> +
 * tag chips (`render`); its text "● status · #tag" stays the tooltip, sort and
 * filter value. DataGrid pins the chip column right after the select cell in
 * this preset. The preset flag is read by the title formatter and set by GridToolbar.
 */

let axiomActive = false;

export function setAxiomMode(active: boolean): void {
  axiomActive = active;
}

export function isAxiomMode(): boolean {
  return axiomActive;
}

const SUBTITLE_MAX = 140;

/** Second line of the AXIOM row: type plus the most telling detail. */
export function axiomSubtitle(row: GridRow): string {
  const f = row.fields;
  const detail =
    str(f.detail) ||
    str(f.keywords) ||
    str(f.message) ||
    str(f.preview) ||
    (typeof f.size === "number" ? formatBytes(f.size) : "") ||
    row.provider ||
    "";
  const parts = [row.artifactType, detail.replace(/\s+/g, " ").trim()].filter(Boolean);
  const text = parts.length ? parts.join(" · ") : baseName(row.sourcePath);
  return text.length > SUBTITLE_MAX ? `${text.slice(0, SUBTITLE_MAX - 1)}…` : text;
}

export function tagStatusText(row: GridRow): string {
  const status = row.reviewStatus ? `● ${REVIEW_LABELS[row.reviewStatus]}` : "";
  const tags = row.tags.map((t) => `#${t}`).join(" ");
  return [status, tags].filter(Boolean).join(" · ");
}

const TAG_STATUS_COLUMN: ColumnSpec = {
  id: "tagstatus",
  header: "태그·상태",
  width: 150,
  minWidth: 90,
  presets: ["axiom"],
  value: (row) => tagStatusText(row),
  render: tagStatusCell,
};

const AXIOM_KEEP = new Set(["title", "tagstatus", "timestamp", "path"]);

function axiomColumns(columns: ColumnSpec[]): ColumnSpec[] {
  const title = columns.find((c) => c.id === "title");
  if (!title) return columns;
  const twoLine: ColumnSpec = {
    ...title,
    presets: [...new Set([...title.presets, "axiom" as const])],
    format: (row) => {
      const first = title.format ? title.format(row) : row.title;
      return axiomActive ? `${first}\n${axiomSubtitle(row)}` : first;
    },
  };
  const tagged = (c: ColumnSpec): ColumnSpec =>
    AXIOM_KEEP.has(c.id) ? { ...c, presets: [...new Set([...c.presets, "axiom" as const])] } : c;
  // The title keeps its place in the collection's own order (artifacts lead with 시각 · 유형,
  // visual-polish S4); the AXIOM preset itself moves title + chip column to the front (DataGrid).
  const at = columns.indexOf(title);
  return [
    ...columns.slice(0, at).map(tagged),
    twoLine,
    TAG_STATUS_COLUMN,
    ...columns.slice(at + 1).map(tagged),
  ];
}

/** Add the AXIOM preset to a collection (title first, chip column second). */
export function withAxiom(def: CollectionDef): CollectionDef {
  const columnsFor = def.columnsFor;
  return {
    ...def,
    columns: axiomColumns(def.columns),
    columnsFor: columnsFor ? (ref, types) => axiomColumns(columnsFor(ref, types)) : undefined,
  };
}
