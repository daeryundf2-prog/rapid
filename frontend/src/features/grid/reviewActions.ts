import { announce } from "../../a11y/announcer";
import { ApiError } from "../../api/client";
import {
  type BookmarkBody,
  type CaseDbHandle,
  ensureCaseDb,
  postBookmark,
  postReviewBatch,
  type ReviewBatchTarget,
  type ReviewMarkBody,
} from "../../api/collections";
import { extractRows, type RunExtractResult } from "../../api/extract";
import type { GridRow, ReviewStatus } from "../../contracts/collection";
import type { MarkAction } from "../../contracts/viewer";
import { useAppStore } from "../../state/store";
import { baseName, str } from "./columns/common";

export type BatchAction = MarkAction | "tag" | "extract";

export const MARK_LABELS: Record<BatchAction, string> = {
  relevant: "관련",
  "needs-review": "재검토",
  excluded: "제외",
  "include-in-report": "보고서 포함",
  bookmark: "북마크",
  tag: "태그",
  extract: "추출",
};

/** Max rows per extract request (API limit). */
export const EXTRACT_LIMIT = 500;

/** Bookmark API target (`source` alias + JSON pointer) for a grid row, or null when unknown. */
export function bookmarkTarget(row: GridRow): { source: string; pointer: string } | null {
  const raw = row.fields.pointer ? str(row.fields.pointer) : row.ref.locator;
  // Search rows may carry "docs-index:/results/3"; the pointer is the part after the scheme.
  const pointer = raw.includes(":/") ? raw.slice(raw.indexOf(":/") + 1) : raw;
  if (!pointer.startsWith("/")) return reviewRowTarget(row);
  if (pointer.startsWith("/candidates/")) return { source: "files", pointer };
  if (pointer.startsWith("/results/")) return { source: "docs", pointer };
  if (pointer.startsWith("/events/")) return { source: "timeline", pointer };
  if (pointer.startsWith("/indicators/") || pointer.startsWith("/ioc_scanner_hits/")) {
    return { source: "indicators", pointer };
  }
  if (pointer.startsWith("/artifacts/") && row.ref.kind)
    return { source: `artifacts:${row.ref.kind}`, pointer };
  return null;
}

/** Review-board rows are bookmarks already; re-target them via their recorded source. */
function reviewRowTarget(row: GridRow): { source: string; pointer: string } | null {
  if (row.ref.collection !== "review") return null;
  const pointer = str(row.fields.pointer);
  if (!pointer.startsWith("/")) return null;
  const command = str(row.fields.sourceCommand);
  const fileMatch = /artifacts_([A-Za-z0-9_-]+)/.exec(baseName(str(row.fields.sourceFile)));
  if (fileMatch?.[1]) return { source: `artifacts:${fileMatch[1]}`, pointer };
  if (["files", "docs", "timeline", "indicators"].includes(command)) return { source: command, pointer };
  return null;
}

interface MarkPayload {
  review_status?: string;
  status?: string;
  include_in_report?: boolean;
  tags?: string[];
  note?: string;
}

function markBody(action: BatchAction, tag?: string): MarkPayload {
  switch (action) {
    case "relevant":
      return { review_status: "relevant", status: "relevant" };
    case "needs-review":
      return { review_status: "needs-review", status: "needs-review" };
    case "excluded":
      return { review_status: "excluded", status: "excluded", include_in_report: false };
    case "include-in-report":
      return { include_in_report: true };
    case "tag":
      return { tags: tag ? [tag] : [] };
    default:
      return { tags: ["북마크"] };
  }
}

/** Optimistic row transform applied immediately; rolled back on failure. */
export function optimisticPatch(action: BatchAction, tag?: string): (row: GridRow) => GridRow {
  return (row) => {
    switch (action) {
      case "relevant":
      case "needs-review":
      case "excluded":
        return { ...row, reviewStatus: action as ReviewStatus };
      case "include-in-report":
        return {
          ...row,
          reviewStatus: row.reviewStatus ?? "include-in-report",
          fields: { ...row.fields, includeInReport: true },
        };
      case "tag":
        return tag && !row.tags.includes(tag) ? { ...row, tags: [...row.tags, tag] } : row;
      case "bookmark":
        return row.tags.includes("북마크") ? row : { ...row, tags: [...row.tags, "북마크"] };
      default:
        return row;
    }
  };
}

function isCaseDbRow(row: GridRow): boolean {
  return typeof row.ref.caseDbId === "number" && typeof row.fields.targetType === "string";
}

/** Run-output locator of a row as the case DB resolves it (`collection` + `kind` + `locator`). */
export function reviewLocatorTarget(
  row: GridRow,
): { collection: string; kind: string; locator: string } | null {
  const target = bookmarkTarget(row);
  if (!target) return null;
  if (target.source.startsWith("artifacts:")) {
    return {
      collection: "artifacts",
      kind: target.source.slice("artifacts:".length),
      locator: target.pointer,
    };
  }
  return { collection: target.source, kind: "", locator: target.pointer };
}

/** The review-batch target for a row: its case-db id, else its run-output locator; null when neither is known. */
export function reviewTargetOf(row: GridRow): ReviewBatchTarget | null {
  if (isCaseDbRow(row))
    return { target_type: str(row.fields.targetType), target_id: String(row.ref.caseDbId) };
  const located = reviewLocatorTarget(row);
  if (!located) return null;
  return located.kind
    ? { collection: located.collection, kind: located.kind, locator: located.locator }
    : { collection: located.collection, locator: located.locator };
}

async function inChunks<T>(items: T[], size: number, work: (item: T) => Promise<unknown>): Promise<void> {
  for (let i = 0; i < items.length; i += size) {
    await Promise.all(items.slice(i, i + size).map(work));
  }
}

/** Where a mark was stored: the run's case DB (canonical) or case.json bookmarks (fallback). */
export type ReviewStore = "case-db" | "bookmarks";

export interface ApplyResult {
  applied: number;
  extract?: RunExtractResult;
  store?: ReviewStore;
}

/** Toast suffix that tells the analyst a mark went to the case.json fallback, not the case DB. */
export const BOOKMARK_FALLBACK_NOTICE = "케이스 DB를 만들 수 없어 case.json 북마크에 저장했습니다";

export function storeNotice(result: ApplyResult): string {
  return result.store === "bookmarks" ? ` (${BOOKMARK_FALLBACK_NOTICE})` : "";
}

// ---- case DB handle (ensure once per run) ----------------------------------

const caseDbHandles = new Map<string, Promise<CaseDbHandle | null>>();
/** Runs whose ensure call has settled (the handle is known; marks apply without waiting). */
const settledRuns = new Set<string>();

/** Forget cached handles (tests; a run re-import). */
export function resetCaseDbHandles(): void {
  caseDbHandles.clear();
  settledRuns.clear();
}

/** Shown while POST /case-db/ensure is still running (first import can take minutes). */
export const CASE_DB_PREPARING_NOTICE = "케이스 DB 준비 중… 완료되면 표시가 적용됩니다";

/** Immediate feedback for a mark that waits on the case DB: one polite sentence + the status-bar notice. */
function notifyPreparing(): void {
  announce(CASE_DB_PREPARING_NOTICE);
  useAppStore.getState().showNotice(CASE_DB_PREPARING_NOTICE);
}

function apiReason(error: ApiError): string {
  return error.message && error.message !== `HTTP ${error.status}` ? error.message : `HTTP ${error.status}`;
}

/**
 * The run's case DB handle via POST /case-db/ensure, once per run. Resolves null
 * when the server says no case DB can be created for this run (4xx); network and
 * 5xx errors reject so the mark fails visibly instead of silently falling back.
 */
function caseDbHandle(runId: string): Promise<CaseDbHandle | null> {
  const cached = caseDbHandles.get(runId);
  if (cached) return cached;
  const pending = ensureCaseDb(runId).then(
    (handle) => {
      settledRuns.add(runId);
      return handle;
    },
    (error: unknown) => {
      caseDbHandles.delete(runId);
      if (error instanceof ApiError && error.status < 500 && error.status !== 401) {
        // Same fallback as before (case.json bookmarks), but say why.
        announce(`케이스 DB를 만들 수 없습니다(${apiReason(error)}). ${BOOKMARK_FALLBACK_NOTICE}`);
        return null;
      }
      throw error;
    },
  );
  caseDbHandles.set(runId, pending);
  return pending;
}

// ---- change listeners (react-query invalidation lives in the app) ----------

type ReviewListener = (runId: string, store: ReviewStore) => void;
const listeners = new Set<ReviewListener>();

/** Subscribe to applied review marks/notes (the app invalidates review-counts / review-map). */
export function onReviewApplied(listener: ReviewListener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/**
 * Apply a review mark to rows. The run's case DB is the canonical store:
 * ensure it once per run, then POST /api/case-db/review-batch with each row's
 * case-db id or run-output locator (the server resolves locators to rows). Only
 * when no case DB can be created does the mark go to the case.json bookmarks.
 */
export async function applyReviewAction(
  runId: string,
  rows: GridRow[],
  action: BatchAction,
  options: { tag?: string } = {},
): Promise<ApplyResult> {
  if (action === "extract") {
    const seen = new Set<string>();
    const items: { path: string; locator: string }[] = [];
    for (const row of rows) {
      if (!row.sourcePath || seen.has(row.sourcePath)) continue;
      seen.add(row.sourcePath);
      items.push({ path: row.sourcePath, locator: row.ref.locator });
    }
    if (items.length === 0) throw new Error("원본 경로가 있는 행이 없습니다.");
    if (items.length > EXTRACT_LIMIT) throw new Error(`한 번에 ${EXTRACT_LIMIT}건까지 추출할 수 있습니다.`);
    const extract = await extractRows(runId, { rows: items });
    return { applied: extract.summary.extracted_count, extract };
  }
  return applyBody(runId, rows, markBody(action, options.tag), caseDbMark(action, options.tag));
}

/** Save one free-text note (X5) on every row; same store routing as review marks. */
export async function applyNote(runId: string, rows: GridRow[], note: string): Promise<ApplyResult> {
  const text = note.trim();
  if (!text) throw new Error("메모 내용이 비어 있습니다.");
  return applyBody(runId, rows, { note: text }, { note: text });
}

function caseDbMark(action: BatchAction, tag?: string): ReviewMarkBody {
  switch (action) {
    case "relevant":
    case "needs-review":
      return { status: action };
    case "excluded":
      return { status: "excluded", include_in_report: false };
    case "include-in-report":
      return { include_in_report: true };
    case "tag":
      return { add_tags: tag ? [tag] : [] };
    default:
      return { add_tags: ["북마크"] };
  }
}

async function applyBody(
  runId: string,
  rows: GridRow[],
  body: MarkPayload,
  mark: ReviewMarkBody,
): Promise<ApplyResult> {
  const targets = rows.map(reviewTargetOf);
  const unresolved = targets.filter((t) => t === null).length;
  if (unresolved > 0) throw new Error(`출처 위치를 알 수 없는 행이 ${unresolved}건 있습니다.`);
  // Queue on the (shared, cached) ensure promise: a mark made while the case DB is still being
  // prepared is applied when it resolves, never dropped; the analyst hears that right away.
  const pending = caseDbHandle(runId);
  if (!settledRuns.has(runId)) notifyPreparing();
  const handle = await pending;
  let store: ReviewStore;
  if (handle) {
    await postReviewBatch(handle, targets as ReviewBatchTarget[], mark, runId);
    store = "case-db";
  } else {
    const bookmarkRows = rows.filter((r) => bookmarkTarget(r) !== null);
    if (bookmarkRows.length !== rows.length) {
      throw new Error("케이스 DB를 만들 수 없고 이 행은 북마크 위치 정보도 없습니다.");
    }
    await inChunks(bookmarkRows, 8, (row) => {
      const target = bookmarkTarget(row) as { source: string; pointer: string };
      const payload: BookmarkBody = { source: target.source, pointer: target.pointer };
      if (body.review_status) payload.review_status = body.review_status;
      if (typeof body.include_in_report === "boolean") payload.include_in_report = body.include_in_report;
      if (body.tags) payload.tags = body.tags;
      if (body.note) payload.note = body.note;
      return postBookmark(runId, payload);
    });
    store = "bookmarks";
  }
  for (const listener of listeners) listener(runId, store);
  return { applied: rows.length, store };
}
