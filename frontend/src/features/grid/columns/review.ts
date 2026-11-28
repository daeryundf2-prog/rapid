import { fetchReviewRows, type RawRow } from "../../../api/collections";
import type { GridRow } from "../../../contracts/collection";
import { formatGridTime, formatMinute } from "../../../utils/time";
import { reviewerLabel } from "../../review/author";
import {
  type BoardTimeKind,
  boardReportCell,
  boardReviewerCell,
  boardTimeCell,
  FILE_TIME_REASON,
  NO_EVENT_TIME_REASON,
} from "../../review/ReviewBoardCells";
import type { CollectionDef } from "../types";
import {
  col,
  currentTimezone,
  fieldStr,
  isRecord,
  makeRef,
  makeRow,
  rowTimeZone,
  sha256Of,
  str,
  strOrNull,
  toReviewStatus,
} from "./common";

const COLLECTION_LABELS: Record<string, string> = {
  files: "파일",
  docs: "문서",
  artifacts: "아티팩트",
  timeline: "타임라인",
  indicators: "IOC",
  analysis: "분석 결과",
};

/** Korean names of case-DB review target types (fallback summary when the server has no label). */
const TARGET_TYPE_LABELS: Record<string, string> = {
  analysis_row: "분석 결과",
  file_record: "파일",
  event: "타임라인 이벤트",
  indexed_document: "문서",
  artifact: "아티팩트",
};

/** "분석 결과 3 (2a942078)" for `analysis_row 20261012T112630-2a942078/2`, never the raw id. */
export function reviewTargetFallback(targetType: string, targetId: string, index: number): string {
  const label = TARGET_TYPE_LABELS[targetType] ?? "검토 항목";
  if (targetType === "analysis_row") {
    const [job = "", row = ""] = targetId.split("/");
    const short = job.split("-").pop()?.slice(0, 8) ?? "";
    const n = /^\d+$/.test(row) ? ` ${Number(row) + 1}` : "";
    return `${label}${n}${short ? ` (${short})` : ""}`;
  }
  return /^\d+$/.test(targetId) ? `${label} #${targetId}` : `${label} ${index + 1}`;
}

/** "Artifact event: srum-app-usage evidence-bundle.zip" → the target first (F12: 대상, not the event wording). */
export function boardTargetTitle(title: string): string {
  return title.replace(/^Artifact event:\s*/i, "").trim() || title;
}

/** First line of a note (the board shows one line; the tooltip and the viewer have the whole note). */
export function noteFirstLine(note: string): string {
  return note.trim().split(/\r?\n/, 1)[0] ?? "";
}

/** 출처 of a mark: "타임라인", "파일", "아티팩트: browser-history" … */
function boardSource(collection: string, targetType: string, targetKind: string | null): string {
  const base = COLLECTION_LABELS[collection] ?? TARGET_TYPE_LABELS[targetType] ?? "";
  return base === "아티팩트" && targetKind ? `${base}: ${targetKind}` : base;
}

/**
 * A case-DB review mark (GET /review-map). The ref carries the case-db id and
 * `fields.targetType`, so re-marking on the board posts the row id directly;
 * `pointer`/`sourceCommand` keep the run-output locator for "같은 출처" jumps. The mark's own
 * facts (판정자, 판정 시각, its version for the conflict check) ride in `fields` (F12/F13/F14).
 */
function mapCaseDbMark(raw: RawRow, index: number) {
  const targetType = str(raw.target_type);
  const targetId = str(raw.target_id);
  const collection = str(raw.collection);
  const kind = strOrNull(raw.kind) ?? undefined;
  const ref = {
    ...makeRef("review", `case-db:${targetType}:${targetId}`, kind),
    ...(/^\d+$/.test(targetId) ? { caseDbId: Number(targetId) } : {}),
  };
  const locator = str(raw.locator);
  const eventTime = strOrNull(raw.timestamp);
  const fileTime = targetType === "file_record" ? strOrNull(raw.file_modified_at) : null;
  const timeKind: BoardTimeKind = eventTime ? "event" : fileTime ? "file-mtime" : "none";
  const targetKind = strOrNull(raw.target_kind);
  return makeRow(
    ref,
    {
      title: boardTargetTitle(
        strOrNull(raw.label) ??
          strOrNull(raw.title) ??
          strOrNull(raw.preview) ??
          reviewTargetFallback(targetType, targetId, index),
      ),
      sourcePath: strOrNull(raw.path),
      // 사건 시각 only: the decision time has its own column (no `?? updated_at` mix-up, F12).
      timestamp: eventTime ?? fileTime,
      artifactType: targetKind ?? (COLLECTION_LABELS[collection] || null),
      reviewStatus: toReviewStatus(raw.status, raw.include_in_report),
      tags: Array.isArray(raw.tags) ? raw.tags.map(str).filter(Boolean) : [],
    },
    {
      targetType,
      pointer: locator,
      sourceCommand: kind ? `artifacts:${kind}` : collection,
      note: str(raw.note),
      includeInReport: raw.include_in_report === true,
      store: "case-db",
      citationId: str(raw.citation_id),
      timeKind,
      reviewer: str(raw.reviewer),
      markUpdatedAt: str(raw.updated_at),
      markCreatedAt: str(raw.created_at),
      changeCount: typeof raw.change_count === "number" ? raw.change_count : 0,
      source: boardSource(collection, targetType, targetKind),
    },
  );
}

/** A case.json bookmark (fallback store when no case DB could be created). */
function mapBookmark(raw: RawRow, index: number) {
  const review = isRecord(raw.review) ? raw.review : {};
  const reference = isRecord(raw.reference) ? raw.reference : {};
  const snapshot = isRecord(raw.snapshot) ? raw.snapshot : {};
  const id = strOrNull(raw.bookmark_id) ?? String(index);
  const eventTime = strOrNull(snapshot.timestamp);
  const command = str(reference.command);
  return makeRow(
    makeRef("review", `bookmark:${id}`),
    {
      title: boardTargetTitle(strOrNull(raw.summary) ?? strOrNull(snapshot.summary) ?? id),
      sourcePath: strOrNull(snapshot.path),
      timestamp: eventTime,
      sha256: sha256Of(snapshot.hash),
      reviewStatus: toReviewStatus(review.status, review.include_in_report),
      tags: Array.isArray(raw.tags) ? raw.tags.map(str).filter(Boolean) : [],
    },
    {
      pointer: str(reference.pointer),
      sourceCommand: command,
      sourceFile: str(reference.file),
      note: str(raw.note),
      includeInReport: review.include_in_report === true,
      store: "bookmarks",
      timeKind: eventTime ? "event" : "none",
      reviewer: str(review.reviewer),
      markUpdatedAt: str(raw.updated_at),
      source: COLLECTION_LABELS[command.split(":")[0] ?? ""] ?? "",
    },
  );
}

/** The 사건 시각 text of a board row ("" when the target has none). */
function boardTimeText(row: GridRow): string {
  return row.timestamp ? formatGridTime(row.timestamp, currentTimezone(), rowTimeZone(row)) : "";
}

/** 판정 시각: "2026-11-27 12:28 KST" (minutes; the header names the zone). */
function decidedAtText(row: GridRow): string {
  const ms = Date.parse(fieldStr(row, "markUpdatedAt"));
  return Number.isNaN(ms) ? "" : formatMinute(ms, currentTimezone());
}

/** "판정자 김철수, 처음 판정 2026-11-27 12:28 KST, 바뀐 횟수 3" — the mark's history at a glance. */
export function reviewerTooltip(row: GridRow): string {
  const parts = [`판정자 ${reviewerLabel(fieldStr(row, "reviewer"))}`];
  const created = Date.parse(fieldStr(row, "markCreatedAt"));
  if (!Number.isNaN(created)) parts.push(`처음 판정 ${formatMinute(created, currentTimezone())}`);
  const count = typeof row.fields.changeCount === "number" ? row.fields.changeCount : 0;
  if (count > 0) parts.push(`바뀐 횟수 ${count}`);
  return parts.join(", ");
}

/**
 * 검토 보드 column priority (narrow panes): 대상 and its 판정 always; then 보고서, 사건 시각, 판정 시각,
 * 판정자, 출처, 경로; 메모 and 태그 give their width back first (390 keeps 판정 · 대상).
 */
const REVIEW_PRIORITY = [
  "title",
  "review",
  "report",
  "timestamp",
  "decidedAt",
  "reviewer",
  "source",
  "path",
  "note",
  "tags",
] as const;

export const reviewCollection: CollectionDef = {
  id: "review",
  label: "검토 보드",
  source: "whole",
  fetch: (runId, _query, signal) => fetchReviewRows(runId, signal),
  mapRow: (raw, index) => (raw._store === "case-db" ? mapCaseDbMark(raw, index) : mapBookmark(raw, index)),
  columns: [
    { ...col.review(), header: "판정" },
    // Report inclusion apart from the 판정: a 관련 있음 mark may or may not be in the report (F12).
    col.field(
      "report",
      "보고서",
      72,
      ["analysis", "compact"],
      (r) => (r.fields.includeInReport === true ? "포함" : "미포함"),
      { render: boardReportCell },
    ),
    { ...col.title("대상", 300), minWidth: 160 },
    // 사건 시각 never narrower than "2026-10-18 08:02:48" at 13px; a file shows its copy's mtime, said so.
    {
      ...col.timestamp(184, ["analysis", "compact", "source"]),
      header: "사건 시각",
      minWidth: 144,
      render: (r) => boardTimeCell(r, boardTimeText(r)),
      tooltip: (r) =>
        r.fields.timeKind === "file-mtime"
          ? `${boardTimeText(r)}: ${FILE_TIME_REASON}`
          : boardTimeText(r) || NO_EVENT_TIME_REASON,
    },
    col.field(
      "decidedAt",
      "판정 시각",
      136,
      ["analysis", "compact", "source"],
      (r) => fieldStr(r, "markUpdatedAt"),
      { minWidth: 128, zoneInHeader: true, filterKind: "time", format: decidedAtText },
    ),
    col.field(
      "reviewer",
      "판정자",
      104,
      ["analysis", "compact", "source"],
      (r) => reviewerLabel(fieldStr(r, "reviewer")),
      { render: (r) => boardReviewerCell(reviewerLabel(fieldStr(r, "reviewer"))), tooltip: reviewerTooltip },
    ),
    col.field("source", "출처", 112, ["analysis", "source"], (r) => fieldStr(r, "source")),
    col.path(240, ["analysis", "source"]),
    col.field("note", "메모", 200, ["analysis"], (r) => noteFirstLine(fieldStr(r, "note")), {
      tooltip: (r) => fieldStr(r, "note"),
    }),
    col.field("tags", "태그", 140, ["analysis", "compact"], (r) => r.tags.join(", ")),
    col.field("pointer", "위치", 160, ["source"], (r) => fieldStr(r, "pointer"), { mono: true }),
  ],
  widthPriority: () => REVIEW_PRIORITY,
};
