/**
 * Citation text and review-mark routing for a ViewerTarget.
 */

import type { GridRow } from "../../contracts/collection";
import type { MarkAction, ViewerTarget } from "../../contracts/viewer";
import { evidenceTime } from "../../utils/time";
import { timestampKindLabel } from "../../utils/timeKinds";
import {
  type ApplyResult,
  applyReviewAction,
  resetCaseDbHandles,
  reviewTargetOf,
} from "../grid/reviewActions";
import { layoutFields, recordIdentifier, recordLayout } from "./fieldSheets";
import { formatOffset } from "./hex";

export const MARK_LABELS: Record<MarkAction, string> = {
  relevant: "관련 있음",
  "needs-review": "재검토",
  excluded: "제외",
  "include-in-report": "보고서 포함",
  bookmark: "북마크",
};

export const MARK_ORDER: MarkAction[] = [
  "relevant",
  "needs-review",
  "excluded",
  "include-in-report",
  "bookmark",
];

export function locatorText(target: ViewerTarget): string {
  const { ref } = target;
  return [ref.collection, ref.kind, ref.locator].filter(Boolean).join(":");
}

/** The record's identifier and time for citations ("EventRecordID 1001", evidence-format time + kind). */
export function recordCitationParts(row: GridRow | null | undefined, tz: string): string[] {
  if (!row) return [];
  const parts: string[] = [];
  const id = recordIdentifier(row);
  if (id) parts.push(`레코드=${id.label} ${id.value}`);
  const layout = recordLayout(row);
  const entry = layout.core.find((e) => e.format === "time" && evidenceTime(scalarOf(e.raw), tz) !== null);
  const value = entry ? scalarOf(entry.raw) : row.timestamp;
  const reading = evidenceTime(value, tz);
  if (reading) {
    const fields = layoutFields(row);
    const own = entry?.key === "timestamp" ? (fields.timestamp_kind ?? fields.timestamp_label) : undefined;
    const kind = typeof own === "string" && own ? own : (entry?.timeKind ?? "");
    const kindText = kind ? `${entry?.label ?? timestampKindLabel(kind)}: ` : "";
    parts.push(`시각=${kindText}${reading.text}`);
  }
  return parts;
}

function scalarOf(value: unknown): string | number | null {
  return typeof value === "string" || typeof value === "number" ? value : null;
}

/**
 * One-line citation: path + container sha256 + locator (+ record id + record time when the row is
 * known) + run id (+ byte range / sqlite row when highlighted).
 */
export function buildCitation(
  target: ViewerTarget,
  sha256: string | null,
  row?: GridRow | null,
  tz = "utc",
): string {
  const isArtifact = target.ref.collection === "artifacts";
  const parts = [
    `원본=${target.sourcePath ?? "(원본 경로 없음)"}`,
    `${row && isArtifact ? "컨테이너 sha256" : "sha256"}=${sha256 || "미계산"}`,
    `위치=${locatorText(target)}`,
    ...recordCitationParts(row, tz),
    `런=${target.runId}`,
  ];
  const highlight = target.highlight;
  if (highlight?.offset !== undefined) {
    const end = highlight.offset + Math.max((highlight.length ?? 1) - 1, 0);
    parts.push(`바이트=${formatOffset(highlight.offset)}-${formatOffset(end)}`);
  }
  if (highlight?.table) {
    parts.push(
      `테이블=${highlight.table}${highlight.rowid !== undefined ? `#rowid ${highlight.rowid}` : ""}`,
    );
  }
  return parts.join("; ");
}

// ---------------------------------------------------------------------------
// Review marks
// ---------------------------------------------------------------------------

/** case.json bookmark source (search.normalize_bookmark_source aliases). */
export function bookmarkSource(target: ViewerTarget): string | null {
  const { collection, kind } = target.ref;
  switch (collection) {
    case "files":
    case "docs":
    case "timeline":
    case "indicators":
      return collection;
    case "artifacts":
      return kind ? `artifacts:${kind}` : null;
    default:
      return null;
  }
}

/**
 * JSON pointer into the run output the bookmark API resolves. Locators that
 * are already pointers ("/candidates/894", "/events/278261") pass through;
 * "artifacts_x:row:N" → "/artifacts/N"; "doc:N" → "/results/N" (CASE_SOURCE_ROWS).
 */
export function bookmarkPointer(target: ViewerTarget): string | null {
  const locator = target.ref.locator;
  if (locator.startsWith("/")) return locator;
  const row = locator.match(/:row:(\d+)$/);
  if (row && target.ref.collection === "artifacts") return `/artifacts/${row[1]}`;
  const doc = locator.match(/^doc:(\d+)$/);
  if (doc && target.ref.collection === "docs") return `/results/${doc[1]}`;
  return null;
}

/** case-db REVIEW_TARGET_TABLES key for a persisted row. */
export function caseDbTargetType(target: ViewerTarget): string | null {
  switch (target.ref.collection) {
    case "artifacts":
      return "artifact";
    case "timeline":
      return "event";
    case "files":
      return "file_record";
    case "docs":
      return "indexed_document";
    case "review":
      // Review-board rows from the case DB: "case-db:<target_type>:<target_id>".
      return /^case-db:([a-z_]+):/.exec(target.ref.locator)?.[1] ?? null;
    default:
      return null;
  }
}

export function markDisabledReason(target: ViewerTarget | null, action: MarkAction): string | undefined {
  if (!target) return "뷰어에 표시된 행이 없습니다.";
  // Same routing as the write path: a case-db id or a run-output locator the case DB resolves.
  if (reviewTargetOf(targetAsGridRow(target))) return undefined;
  return action === "bookmark"
    ? "이 행은 북마크할 수 있는 위치 정보(locator)가 없습니다."
    : "이 행은 리뷰 표시를 저장할 위치 정보(locator)가 없습니다.";
}

/**
 * The ViewerTarget as the GridRow shape the shared review implementation
 * (features/grid/reviewActions.ts `applyReviewAction`) expects: the bookmark
 * pointer and the case-db target type are resolved here, so the grid batch
 * bar, the viewer toolbar and the R/X/I/B · 1–5 keys post identical requests.
 */
export function targetAsGridRow(target: ViewerTarget): GridRow {
  const pointer = bookmarkPointer(target);
  const targetType = caseDbTargetType(target);
  const fields: Record<string, unknown> = {};
  if (pointer) fields.pointer = pointer;
  if (target.ref.caseDbId !== undefined && targetType) fields.targetType = targetType;
  return {
    rowKey: target.ref.kind
      ? `${target.ref.collection}:${target.ref.kind}:${target.ref.locator}`
      : `${target.ref.collection}:${target.ref.locator}`,
    ref: target.ref,
    title: target.sourcePath ?? target.ref.locator,
    sourcePath: target.sourcePath,
    timestamp: null,
    artifactType: null,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields,
  };
}

/** Apply a mark through the shared review implementation (case-db review-batch or case.json bookmark). */
export async function applyMark(target: ViewerTarget, action: MarkAction): Promise<ApplyResult> {
  const reason = markDisabledReason(target, action);
  if (reason) throw new Error(reason);
  return applyReviewAction(target.runId, [targetAsGridRow(target)], action);
}

/** Tests: forget the per-run case-db handles cached by the shared review implementation. */
export function clearCaseDbCache(): void {
  resetCaseDbHandles();
}
