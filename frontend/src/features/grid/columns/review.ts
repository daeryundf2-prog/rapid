import { createElement } from "react";
import { fetchReviewRows, type RawRow } from "../../../api/collections";
import type { GridRow } from "../../../contracts/collection";
import { artifactTypeLabel } from "../../filters/typeLabels";
import type { CollectionDef } from "../types";
import {
  col,
  fieldStr,
  isRecord,
  makeRef,
  makeRow,
  REVIEW_LABELS,
  sha256Of,
  str,
  strOrNull,
  TIME_COLUMN_MIN,
  toReviewStatus,
} from "./common";
import { reviewStatusCell } from "./StatusCells";

const COLLECTION_LABELS: Record<string, string> = {
  files: "파일",
  docs: "문서",
  artifacts: "아티팩트",
  timeline: "타임라인",
  indicators: "IOC",
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

/** A leading "<id>:" whose id may be a type id (the catalogue decides; no generic pattern, T-176). */
const LEADING_ID = /^([A-Za-z0-9][\w.-]*)\s*:\s*/;

/**
 * The 요약 of a review row without the internal type-id prefix (T-176, GAP-090): "prefetch-file:
 * CHROME.EXE" → "CHROME.EXE". Only the row's own kind or an id the artifact type catalogue knows is
 * dropped: timestamps ("2026-01-01T10:23:45 …"), addresses ("192.168.0.5:445 …"), host names and
 * file names ("setup.exe: 3 runs") stay whole. A summary that is only the type id reads as the
 * type's Korean name.
 */
export function reviewSummary(text: string | null, kind?: string | null): string | null {
  const raw = (text ?? "").trim();
  if (!raw) return null;
  const typeId = (kind ?? "").trim();
  if (typeId && raw.toLowerCase() === typeId.toLowerCase()) return artifactTypeLabel(typeId) ?? null;
  let rest = raw;
  if (typeId && rest.toLowerCase().startsWith(`${typeId.toLowerCase()}:`)) {
    rest = rest.slice(typeId.length + 1).trim();
  } else {
    const lead = LEADING_ID.exec(rest);
    if (lead?.[1] && artifactTypeLabel(lead[1]) !== null) rest = rest.slice(lead[0].length).trim();
  }
  if (rest) return rest;
  return typeId ? (artifactTypeLabel(typeId) ?? null) : null;
}

/** The row is marked for the report: the include flag, or the include-only review status. */
export function inReport(row: GridRow): boolean {
  return row.fields.includeInReport === true || row.reviewStatus === "include-in-report";
}

/** Marker shown in the 보고서 column (T-176): never in the 검토 verdict chip slot. */
export const REPORT_MARKER = "보고서 포함";

/**
 * A case-DB review mark (GET /review-map). The ref carries the case-db id and
 * `fields.targetType`, so re-marking on the board posts the row id directly;
 * `pointer`/`sourceCommand` keep the run-output locator for "같은 출처" jumps.
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
  return makeRow(
    ref,
    {
      title:
        reviewSummary(strOrNull(raw.label), strOrNull(raw.target_kind)) ??
        reviewSummary(strOrNull(raw.title), strOrNull(raw.target_kind)) ??
        reviewSummary(strOrNull(raw.preview), strOrNull(raw.target_kind)) ??
        reviewTargetFallback(targetType, targetId, index),
      sourcePath: strOrNull(raw.path),
      timestamp: strOrNull(raw.timestamp) ?? strOrNull(raw.updated_at),
      artifactType: strOrNull(raw.target_kind) ?? (COLLECTION_LABELS[collection] || null),
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
    },
  );
}

/** A case.json bookmark (fallback store when no case DB could be created). */
function mapBookmark(raw: RawRow, index: number) {
  const review = isRecord(raw.review) ? raw.review : {};
  const reference = isRecord(raw.reference) ? raw.reference : {};
  const snapshot = isRecord(raw.snapshot) ? raw.snapshot : {};
  const id = strOrNull(raw.bookmark_id) ?? String(index);
  return makeRow(
    makeRef("review", `bookmark:${id}`),
    {
      title: reviewSummary(strOrNull(raw.summary)) ?? reviewSummary(strOrNull(snapshot.summary)) ?? id,
      sourcePath: strOrNull(snapshot.path),
      timestamp: strOrNull(snapshot.timestamp) ?? strOrNull(raw.updated_at),
      sha256: sha256Of(snapshot.hash),
      reviewStatus: toReviewStatus(review.status, review.include_in_report),
      tags: Array.isArray(raw.tags) ? raw.tags.map(str).filter(Boolean) : [],
    },
    {
      pointer: str(reference.pointer),
      sourceCommand: str(reference.command),
      sourceFile: str(reference.file),
      note: str(raw.note),
      includeInReport: review.include_in_report === true,
      store: "bookmarks",
    },
  );
}

export const reviewCollection: CollectionDef = {
  id: "review",
  label: "검토 목록",
  source: "whole",
  fetch: (runId, _query, signal) => fetchReviewRows(runId, signal),
  mapRow: (raw, index) => (raw._store === "case-db" ? mapCaseDbMark(raw, index) : mapBookmark(raw, index)),
  columns: [
    {
      // The verdict slot holds the judgement only; 보고서 포함 is its own marker (T-176).
      ...col.review(),
      value: (r) => (r.reviewStatus === "include-in-report" ? null : r.reviewStatus),
      format: (r) =>
        r.reviewStatus && r.reviewStatus !== "include-in-report" ? REVIEW_LABELS[r.reviewStatus] : "",
      render: (r) => (r.reviewStatus === "include-in-report" ? null : reviewStatusCell(r)),
    },
    col.title("요약", 340),
    col.field("tags", "태그", 160, ["analysis", "compact"], (r) => r.tags.join(", ")),
    col.field("note", "메모", 260, ["analysis"], (r) => fieldStr(r, "note")),
    col.field("report", "보고서", 104, ["analysis", "compact"], (r) => (inReport(r) ? REPORT_MARKER : ""), {
      format: (r) => (inReport(r) ? REPORT_MARKER : ""),
      render: (r) =>
        inReport(r)
          ? createElement(
              "span",
              { className: "grid-tag-chip", "data-testid": "review-report-marker" },
              REPORT_MARKER,
            )
          : null,
    }),
    // 시각 never narrower than its 15 characters + padding (review #9: no clipped seconds).
    col.timestamp(TIME_COLUMN_MIN, ["analysis", "source"]),
    col.path(420, ["source"]),
    col.field("pointer", "위치", 160, ["source"], (r) => fieldStr(r, "pointer"), { mono: true }),
  ],
};
