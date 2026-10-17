/**
 * CSV of the grid selection (AXIOM E3, research §4 export convention): 태그 · 메모 · the grid's
 * visible columns · then seven fixed trailing columns every row carries —
 * 소스 · 위치 · 복구 방법 · 증거 번호 · 사건 번호 · 항목 ID · 파서 버전 — each filled or "없음".
 * UTF-8 with BOM and CRLF rows so Excel opens Korean text correctly. A cell that Excel would
 * run as a formula (=, +, @, a tab/CR, or "-" not followed by a number) gets a leading ' so
 * evidence text can never execute (CSV injection).
 */

import type { ExportContext } from "../../api/reviewTools";
import type { GridRow } from "../../contracts/collection";
import { isRecord, str } from "../grid/columns/common";
import type { ColumnSpec } from "../grid/types";
import { evidenceInfo } from "../viewer/evidenceInfo";

export const NONE = "없음";
export const TRAILING_HEADERS = [
  "소스",
  "위치",
  "복구 방법",
  "증거 번호",
  "사건 번호",
  "항목 ID",
  "파서 버전",
] as const;
export const LEADING_HEADERS = ["태그", "메모"] as const;
export const CSV_BOM = "﻿";
/** Rows per export (the selection is held in memory as one string). */
export const CSV_MAX_ROWS = 10_000;

const FORMULA_START = /^[=+@\t\r]|^-(?![\d.])/;

/** One CSV field: formula-guarded, quoted when it holds a comma, quote or line break. */
export function csvCell(value: unknown): string {
  let text = value === null || value === undefined ? "" : typeof value === "string" ? value : str(value);
  if (FORMULA_START.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function filled(value: string | null | undefined): string {
  const text = (value ?? "").trim();
  return text && text !== "—" ? text : NONE;
}

/** "파서 v1.2" from the row's record (details.parser / parser_version / evtx_decoder_version). */
export function parserVersionOf(row: GridRow): string {
  const details = isRecord(row.fields.details) ? row.fields.details : {};
  const name = [details.parser, row.ref.collection === "timeline" ? null : row.provider].find(
    (v): v is string => typeof v === "string" && v.length > 0,
  );
  const version = [details.parser_version, details.evtx_decoder_version, row.fields.parserVersion].find(
    (v) => (typeof v === "string" && v) || typeof v === "number",
  );
  const versionText =
    version === undefined ? "" : /^\d/.test(String(version)) ? `v${String(version)}` : String(version);
  return [name, versionText].filter(Boolean).join(" ");
}

/** Stable per-run row id: the grid row key `<collection>[:<kind>]:<locator>`. */
export function itemIdOf(row: GridRow): string {
  return row.rowKey || [row.ref.collection, row.ref.kind, row.ref.locator].filter(Boolean).join(":");
}

export function locationOf(row: GridRow): string {
  const { offset } = evidenceInfo(row);
  if (offset === null) return NONE;
  return `오프셋 ${offset} (0x${offset.toString(16).toUpperCase()})`;
}

export function trailingValues(row: GridRow, context: Partial<ExportContext> | null): string[] {
  return [
    filled(row.sourcePath),
    locationOf(row),
    filled(evidenceInfo(row).recovery),
    filled(context?.evidence_number),
    filled(context?.case_number),
    filled(itemIdOf(row)),
    filled(parserVersionOf(row)),
  ];
}

function columnText(column: ColumnSpec, row: GridRow): string {
  try {
    if (column.format) return column.format(row);
    const value = column.value(row);
    return value === null || value === undefined ? "" : String(value);
  } catch {
    return "";
  }
}

/** The CSV document (BOM + header + one CRLF line per row). */
export function buildSelectionCsv(
  rows: readonly GridRow[],
  columns: readonly ColumnSpec[],
  context: Partial<ExportContext> | null,
): string {
  const reserved = new Set<string>([...LEADING_HEADERS, ...TRAILING_HEADERS]);
  const middle = columns.filter((column) => !reserved.has(column.header));
  const header = [...LEADING_HEADERS, ...middle.map((column) => column.header), ...TRAILING_HEADERS];
  const lines = [header.map(csvCell).join(",")];
  for (const row of rows) {
    const note = typeof row.fields.note === "string" ? row.fields.note : "";
    const cells = [
      row.tags.join("; "),
      note,
      ...middle.map((column) => columnText(column, row)),
      ...trailingValues(row, context),
    ];
    lines.push(cells.map(csvCell).join(","));
  }
  return `${CSV_BOM}${lines.join("\r\n")}\r\n`;
}

/** Hand a CSV string to the browser as a download. */
export function downloadCsv(fileName: string, csv: string): void {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
