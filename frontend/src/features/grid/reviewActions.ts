import { announce } from "../../a11y/announcer";
import { type ReviewConflict, reviewConflictsOf } from "../../api/caseDb";
import { ApiError } from "../../api/client";
import {
  type BookmarkBody,
  type CaseDbHandle,
  ensureCaseDb,
  postBookmark,
  postReviewBatch,
  type ReviewBatchAnswer,
  type ReviewBatchTarget,
  type ReviewMarkBody,
} from "../../api/collections";
import { extractRows, type RunExtractResult } from "../../api/extract";
import type { GridRow, ReviewStatus } from "../../contracts/collection";
import type { MarkAction } from "../../contracts/viewer";
import { useAppStore } from "../../state/store";
import { currentReviewer } from "../review/author";
import {
  currentVersion,
  type MarkAddress,
  noteSeenVersion,
  noteWrittenMarks,
  resolvePin,
  reviewKey,
  type WrittenMark,
} from "../review/markVersions";
import { type ConflictChoice, conflictSentence, useReviewConflict } from "../review/reviewConflict";
import { baseName, currentTimezone, str } from "./columns/common";

export type BatchAction = MarkAction | "tag" | "extract" | UnmarkAction;

/**
 * Undo of a pressed review toggle: "clear-review" puts the status back to the case DB's
 * `unreviewed` (core/case.py REVIEW_STATUSES); "remove-from-report" clears include_in_report.
 */
export type UnmarkAction = "clear-review" | "remove-from-report";

/** The undo of a pressed mark (bookmark tags are not removed here). */
export function unmarkActionOf(action: string): UnmarkAction | null {
  if (action === "relevant" || action === "needs-review" || action === "excluded") return "clear-review";
  if (action === "include-in-report") return "remove-from-report";
  return null;
}

export const MARK_LABELS: Record<BatchAction, string> = {
  relevant: "관련",
  "needs-review": "재검토",
  excluded: "제외",
  "include-in-report": "보고서 포함",
  bookmark: "북마크",
  tag: "태그",
  extract: "추출",
  "clear-review": "선별 해제",
  "remove-from-report": "보고서 포함 해제",
};

/** Max rows per extract request (API limit). */
export const EXTRACT_LIMIT = 500;

/** Bookmark API target (`source` alias + JSON pointer) for a grid row, or null when unknown. */
export function bookmarkTarget(row: GridRow): { source: string; pointer: string } | null {
  const raw = row.fields.pointer ? str(row.fields.pointer) : row.ref.locator;
  // Search rows may carry "docs-index:/results/3"; the pointer is the part after the scheme.
  const pointer = raw.includes(":/") ? raw.slice(raw.indexOf(":/") + 1) : raw;
  if (!pointer.startsWith("/")) return reviewRowTarget(row);
  // docs.json lists every document under `candidates` (parser-quality r1): same prefix as files.
  if (row.ref.collection === "docs") return { source: "docs", pointer };
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
    case "clear-review":
      return { review_status: "unreviewed", status: "unreviewed" };
    case "remove-from-report":
      return { include_in_report: false };
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
      case "clear-review":
        return {
          ...row,
          reviewStatus: row.fields.includeInReport === true ? "include-in-report" : null,
        };
      case "remove-from-report":
        return {
          ...row,
          reviewStatus: row.reviewStatus === "include-in-report" ? null : row.reviewStatus,
          fields: { ...row.fields, includeInReport: false },
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
  // Analysis result rows: the case DB maps `{collection:"analysis", kind:<analysis_id>, locator:"/rows/<n>"}`.
  if (row.ref.collection === "analysis") {
    return row.ref.kind && row.ref.locator.startsWith("/rows/")
      ? { collection: "analysis", kind: row.ref.kind, locator: row.ref.locator }
      : null;
  }
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
  /**
   * Case-DB writes: per row (same order), the version of the mark this write stored. A later write
   * that must not overwrite someone else's change since (an undo) passes it back as `expected`.
   */
  versions?: Array<number | undefined>;
}

/**
 * Per row (same order), the version of the mark the examiner saw when the edit began (F14, P1-1):
 * a write refuses (409 + conflict prompt) when the stored mark changed since. `undefined` for a row
 * = no check. Take it with `pinExpected` when a form opens, or from a previous `ApplyResult.versions`.
 */
export type ExpectedVersions = ReadonlyArray<number | undefined>;

/** Options of a review write. */
export interface ApplyOptions {
  /** Pinned versions (`pinExpected`); omitted = the versions drawn on `rows` right now. */
  expected?: ExpectedVersions;
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
  options: ApplyOptions & { tag?: string } = {},
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
  return applyBody(
    runId,
    rows,
    markBody(action, options.tag),
    caseDbMark(action, options.tag),
    MARK_LABELS[action],
    options.expected,
  );
}

/** Save one free-text note (X5) on every row; same store routing as review marks. */
export async function applyNote(
  runId: string,
  rows: GridRow[],
  note: string,
  options: ApplyOptions = {},
): Promise<ApplyResult> {
  const text = note.trim();
  if (!text) throw new Error("메모 내용이 비어 있습니다.");
  return applyBody(runId, rows, { note: text }, { note: text }, "메모", options.expected);
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
    case "clear-review":
      return { status: "unreviewed" };
    case "remove-from-report":
      return { include_in_report: false };
    case "tag":
      return { add_tags: tag ? [tag] : [] };
    default:
      return { add_tags: ["북마크"] };
  }
}

/**
 * The write was refused (409, F14): another examiner changed a mark after this console read it.
 * Nothing was written; the conflict prompt (ReviewToolsHost) asks what to do. `choice` settles
 * with the examiner's answer once the prompt's write is done: a form keeps its text on "keep"
 * (review P3-4) and treats "mine" as saved.
 */
export class ReviewConflictError extends Error {
  readonly conflicts: ReviewConflict[];
  readonly choice: Promise<ConflictChoice>;

  constructor(conflicts: ReviewConflict[], tz: string, choice: Promise<ConflictChoice>) {
    const first = conflicts[0];
    const more = conflicts.length > 1 ? ` 외 ${conflicts.length - 1}건` : "";
    super(
      `${first ? conflictSentence(first, tz) : "다른 판정이 먼저 저장됨"}${more}. 저장하지 않았습니다. 내 판정으로 바꿀지 고르세요.`,
    );
    this.name = "ReviewConflictError";
    this.conflicts = conflicts;
    this.choice = choice;
  }
}

/** Where a row's write goes, for its versions: its case-DB target, else its locator. */
function markAddress(target: ReviewBatchTarget): MarkAddress {
  return "target_type" in target
    ? { target: `${target.target_type}:${target.target_id}` }
    : { locator: reviewKey(target.collection, target.kind ?? "", target.locator) };
}

/**
 * What each row's write expects right now: the version drawn on the row (`fields.markVersion`, set
 * by the review-map overlay and the board), else the newest version the console knows. Call it
 * when an edit begins and pass the result as `expected` (P1-1): a review-map reload while the form
 * is open must not move it.
 */
export function pinExpected(runId: string, rows: readonly GridRow[]): ExpectedVersions {
  return rows.map((row) => {
    if (typeof row.fields.markVersion === "number") return row.fields.markVersion;
    const target = reviewTargetOf(row);
    return target ? currentVersion(runId, markAddress(target)) : undefined;
  });
}

function sameTarget(conflict: ReviewConflict, target: ReviewBatchTarget): boolean {
  if ("target_type" in target) {
    return target.target_type === conflict.target_type && target.target_id === conflict.target_id;
  }
  return (
    target.collection === conflict.collection &&
    target.locator === conflict.locator &&
    (target.kind ?? "") === (conflict.kind ?? "")
  );
}

/**
 * Record the versions a successful write of this console stored (review-batch marks, or a tag
 * batch's `marks`), so its next write on those rows does not conflict with itself (P3-2). A mark
 * names its own locator, or `targets[i]` does (review-batch answers keep them in step).
 */
export function rememberWrite(
  runId: string,
  answer: {
    marks?: ReadonlyArray<Record<string, unknown>>;
    targets?: ReadonlyArray<Record<string, unknown>>;
  },
): WrittenMark[] {
  const marks = Array.isArray(answer.marks) ? answer.marks : [];
  const targets = Array.isArray(answer.targets) ? answer.targets : [];
  const written: WrittenMark[] = [];
  marks.forEach((mark, index) => {
    const at = typeof mark.locator === "string" ? mark : targets[index];
    const { target_type: type, target_id: id, version, previous_version: previous } = mark;
    if (typeof type !== "string" || typeof id !== "string") return;
    if (typeof version !== "number" || typeof previous !== "number") return;
    const locatorKey =
      at && typeof at.collection === "string" && typeof at.locator === "string"
        ? reviewKey(at.collection, typeof at.kind === "string" ? at.kind : "", at.locator)
        : null;
    written.push({ target_type: type, target_id: id, previous_version: previous, version, locatorKey });
  });
  noteWrittenMarks(runId, written);
  return written;
}

/**
 * POST the marks; a 409 `review-conflict` opens the conflict prompt and rejects with
 * ReviewConflictError (nothing was written). The prompt's choices post again from here.
 * Resolves with the stored version per target.
 */
async function postChecked(
  runId: string,
  handle: CaseDbHandle,
  targets: ReviewBatchTarget[],
  rows: GridRow[],
  mark: ReviewMarkBody,
  label: string,
): Promise<Array<number | undefined>> {
  let answer: ReviewBatchAnswer;
  try {
    answer = await postReviewBatch(handle, targets, mark, runId);
  } catch (error) {
    const conflicts =
      error instanceof ApiError && error.status === 409 ? reviewConflictsOf(error.detail) : null;
    if (!conflicts || conflicts.length === 0) throw error;
    const choice = openConflictPrompt(runId, handle, targets, rows, mark, label, conflicts);
    throw new ReviewConflictError(conflicts, currentTimezone(), choice);
  }
  // The answer lists case-DB targets before resolved locators: match each request target by address.
  const written = rememberWrite(runId, answer);
  return targets.map((target) => {
    const address = markAddress(target);
    const hit = written.find((mark) =>
      "target" in address
        ? `${mark.target_type}:${mark.target_id}` === address.target
        : mark.locatorKey === address.locator,
    );
    return hit?.version;
  });
}

function openConflictPrompt(
  runId: string,
  handle: CaseDbHandle,
  targets: ReviewBatchTarget[],
  rows: GridRow[],
  mark: ReviewMarkBody,
  label: string,
  conflicts: ReviewConflict[],
): Promise<ConflictChoice> {
  const conflictOf = (target: ReviewBatchTarget) => conflicts.find((c) => sameTarget(c, target));
  const others = targets.filter((target) => !conflictOf(target));
  const sentence = conflictSentence(conflicts[0] as ReviewConflict, currentTimezone());
  let settle: (choice: ConflictChoice) => void = () => {};
  const choice = new Promise<ConflictChoice>((resolve) => {
    settle = resolve;
  });
  // "내 판정으로" met a third change: its own prompt replaces this one and answers for it.
  let followed = false;
  useReviewConflict.getState().open({
    runId,
    conflicts,
    titles: conflicts.map((c) => rows[targets.findIndex((target) => sameTarget(c, target))]?.title ?? ""),
    others: others.length,
    action: label,
    ...(typeof mark.note === "string" ? { mine: { note: mark.note } } : {}),
    resolve: async (picked) => {
      // Either way the examiner has now seen the current marks: a pin on the version this write
      // expected means the reported one from here on (no second prompt for the same change).
      for (const target of targets) {
        const conflict = conflictOf(target);
        if (conflict && "expected_version" in target && typeof target.expected_version === "number")
          noteSeenVersion(runId, markAddress(target), target.expected_version, conflict.current.version);
      }
      if (picked === "mine") {
        // Overwrite exactly the versions the conflict reported; a third change conflicts again.
        const again = targets.map((target) => {
          const conflict = conflictOf(target);
          return conflict ? { ...target, expected_version: conflict.current.version } : target;
        });
        followed = true;
        try {
          await postChecked(runId, handle, again, rows, mark, label);
        } catch (error) {
          if (error instanceof ReviewConflictError) void error.choice.then(settle);
          else followed = false;
          throw error;
        }
        announce(`내 판정으로 바꿨습니다: ${label} ${targets.length}건.`);
      } else {
        const keptRows = rows.filter((_, index) => !conflictOf(targets[index] as ReviewBatchTarget));
        if (others.length > 0) await postChecked(runId, handle, others, keptRows, mark, label);
        announce(
          others.length > 0
            ? `다른 판정 ${conflicts.length}건은 그대로 두고 나머지 ${others.length}건에 적용했습니다(${label}).`
            : "다른 판정을 그대로 두었습니다.",
        );
      }
      // Either way the console shows the stored marks now.
      for (const listener of listeners) listener(runId, "case-db");
      settle(picked);
    },
    abandon: () => {
      if (!followed) settle("keep");
    },
  });
  announce(`판정 충돌: ${sentence}. 저장하지 않았습니다.`, { politeness: "assertive" });
  return choice;
}

async function applyBody(
  runId: string,
  rows: GridRow[],
  body: MarkPayload,
  mark: ReviewMarkBody,
  // What the conflict prompt calls this write; callers that restore or replay marks keep the default.
  label = "판정",
  expected?: ExpectedVersions,
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
  let versions: Array<number | undefined> | undefined;
  if (handle) {
    // The configured review author (AXIOM E3) rides on every mark; "web-ui" when unset.
    const authored: ReviewMarkBody = { ...mark, reviewer: currentReviewer() };
    // F14 / P1-1: each target carries the version the examiner saw (pinned when the edit began,
    // moved only by this console's own writes), so another examiner's newer decision is never
    // overwritten silently (no version known → no check, the old behaviour).
    const pins = expected ?? pinExpected(runId, rows);
    const checked = (targets as ReviewBatchTarget[]).map((target, index) => {
      const version = resolvePin(runId, markAddress(target), pins[index]);
      return version === undefined ? target : { ...target, expected_version: version };
    });
    versions = await postChecked(runId, handle, checked, rows, authored, label);
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
  return {
    applied: rows.length,
    store,
    ...(versions?.some((version) => version !== undefined) ? { versions } : {}),
  };
}

// ---- review tools (AXIOM E3) ---------------------------------------------

/**
 * The run's case DB handle (POST /case-db/ensure once per run, shared with the marks above);
 * null when the server says no case DB can be created for this run.
 */
export function ensureRunCaseDb(runId: string): Promise<CaseDbHandle | null> {
  const pending = caseDbHandle(runId);
  if (!settledRuns.has(runId)) notifyPreparing();
  return pending;
}

/** Tell the listeners (review-map / review-counts invalidation) that marks of the run changed. */
export function notifyReviewApplied(runId: string): void {
  for (const listener of listeners) listener(runId, "case-db");
}
