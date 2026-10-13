import { fetchReviewRows, type RawRow } from "../../../api/collections";
import type { CollectionDef } from "../types";
import {
  col,
  fieldStr,
  isRecord,
  makeRef,
  makeRow,
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
        strOrNull(raw.label) ??
        strOrNull(raw.title) ??
        strOrNull(raw.preview) ??
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
      title: strOrNull(raw.summary) ?? strOrNull(snapshot.summary) ?? id,
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
  label: "리뷰보드",
  source: "whole",
  fetch: (runId, _query, signal) => fetchReviewRows(runId, signal),
  mapRow: (raw, index) => (raw._store === "case-db" ? mapCaseDbMark(raw, index) : mapBookmark(raw, index)),
  columns: [
    col.review(),
    col.title("요약", 340),
    col.field("tags", "태그", 160, ["analysis", "compact"], (r) => r.tags.join(", ")),
    col.field("note", "메모", 260, ["analysis"], (r) => fieldStr(r, "note")),
    col.field("report", "보고서", 80, ["analysis", "compact"], (r) =>
      r.fields.includeInReport ? "포함" : "",
    ),
    // 시각 never narrower than its 15 characters + padding (review #9: no clipped seconds).
    { ...col.timestamp(170, ["analysis", "source"]), minWidth: 150 },
    col.path(420, ["source"]),
    col.field("pointer", "위치", 160, ["source"], (r) => fieldStr(r, "pointer"), { mono: true }),
  ],
};
