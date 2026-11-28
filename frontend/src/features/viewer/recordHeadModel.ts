/**
 * The first lines of the detail for a row that points at a decoded record (design-viewer-keys
 * F18): what the record is about (대상), what its time means ("마지막 방문 시각"), the evidence id,
 * the source file and where in it the record sits — or, when no record locator exists, that the
 * trail ends at the file ("파일 단위까지 추적"). Pure, so the wording is unit-tested.
 */

import type { GridRow } from "../../contracts/collection";
import type { ViewerTarget } from "../../contracts/viewer";
import type { Route } from "../../router";
import { timestampKindLabel } from "../../utils/timeKinds";
import { caseCitationParts } from "../case/caseLink";
import { isRecord } from "../grid/columns/common";
import { recordCitationParts, recordTime } from "./citation";
import { layoutFields } from "./fieldSheets";
import { formatOffset } from "./hex";
import { recordTargetValue } from "./pivots";
import { recordByteRange } from "./record";
import { sourceRecordRef } from "./sourceRecord";

export const FILE_LEVEL_ONLY = "파일 단위까지 추적";

export type RecordOpen =
  | { kind: "hex"; offset: number; length?: number }
  | { kind: "sqlite"; table: string; rowid?: number }
  | { kind: "route"; route: Route };

export interface RecordHeadModel {
  target: string | null;
  /** "마지막 방문 시각" + the evidence-format time. */
  time: { label: string; text: string } | null;
  /** 증거 번호 of the run's case, else null (the head names the run instead). */
  evidence: string | null;
  sourcePath: string | null;
  /** Where in the source file the record is; empty = the trail ends at the file. */
  locator: string[];
  /** What 원본 위치 열기 opens; null when there is no record location. */
  open: RecordOpen | null;
}

/** True for rows the head is for: decoded artifact rows and timeline events with a source record. */
export function hasRecordHead(row: GridRow | null, runId: string | null): boolean {
  if (!row) return false;
  return row.ref.collection === "artifacts" || sourceRecordRef(row, runId) !== null;
}

/** "Artifact event: browser-history https://…" → "https://…" (the list row's own summary). */
export function plainTitle(title: string): string {
  return title.replace(/^Artifact event:\s*\S+\s+/, "").trim();
}

function timeLabel(kind: string): string {
  if (!kind) return "시각";
  return /시각$/.test(kind) ? kind : `${kind} 시각`;
}

export function recordHeadModel(
  row: GridRow,
  decoded: GridRow | null,
  target: ViewerTarget,
  tz: string,
  /** The viewer can show this file as SQLite (the table / row can be opened there). */
  sqliteAvailable = false,
): RecordHeadModel {
  const record = decoded ?? row;
  const fields = layoutFields(record);
  const details = isRecord(record.fields.details) ? record.fields.details : {};
  const titleField = typeof details.title === "string" && details.title.trim() ? details.title.trim() : null;
  const targetText = recordTargetValue(row, decoded) ?? titleField ?? (plainTitle(row.title) || null);

  // The time the row is about (the event's own time) and what it means.
  const time = recordTime(row, tz);
  const ownKind =
    typeof row.fields.tsKind === "string" && row.fields.tsKind ? timestampKindLabel(row.fields.tsKind) : "";
  // The row's own time kind first (a timeline event's "마지막 방문"); a sheet's generic "시각" says nothing.
  const kind = ownKind || (time?.kind === "시각" ? "" : (time?.kind ?? ""));
  const timeLine = time ? { label: timeLabel(kind), text: time.reading.text } : null;

  const evidence =
    caseCitationParts(target.runId)
      .find((part) => part.startsWith("증거="))
      ?.slice("증거=".length) ?? null;

  const locator = recordCitationParts(record, tz).filter((part) => !part.startsWith("시각="));
  const source = sourceRecordRef(row, target.runId);
  if (source) locator.push(`원본 레코드=${source.output} #${source.index}`);
  const table = typeof fields.source_table === "string" && fields.source_table ? fields.source_table : null;
  const rowid = typeof fields.source_row_id === "number" ? fields.source_row_id : undefined;
  if (table) locator.push(`SQLite ${table} 테이블${rowid !== undefined ? ` 행 id ${rowid}` : ""}`);
  const range = recordByteRange(record) ?? (target.highlight?.offset !== undefined ? target.highlight : null);
  if (range?.offset !== undefined) {
    const end = range.offset + Math.max((range.length ?? 1) - 1, 0);
    locator.push(`바이트=${formatOffset(range.offset)}-${formatOffset(end)}`);
  }

  let open: RecordOpen | null = null;
  if (range?.offset !== undefined) open = { kind: "hex", offset: range.offset, length: range.length };
  else if (table && sqliteAvailable)
    open = { kind: "sqlite", table, ...(rowid !== undefined ? { rowid } : {}) };
  else if (source) open = { kind: "route", route: source.route };

  return {
    target: targetText,
    time: timeLine,
    evidence,
    sourcePath: target.sourcePath ?? record.sourcePath ?? null,
    locator,
    open,
  };
}
