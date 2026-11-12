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
import { getReviewHistory } from "../../api/reviewTools";
import { getRun } from "../../api/runs";
import { runCommand } from "../../commands/registry";
import { type ToastAction, useToastStore } from "../../components/toastStore";
import type { GridRow, ReviewStatus } from "../../contracts/collection";
import { KEY_MAP } from "../../contracts/command";
import type { MarkAction } from "../../contracts/viewer";
import { useAppStore } from "../../state/store";
import { currentReviewer } from "../review/author";
import { baseName, str } from "./columns/common";

export type BatchAction = MarkAction | "tag" | "extract" | UnmarkAction;

/**
 * Un-press of a review toggle: "clear-review" puts the status back to the row's previous state
 * (r8 T-036 — the state before the pressed mark: this session's mark stack, else the row's case-DB
 * history, else `unreviewed`); "remove-from-report" clears include_in_report.
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

/**
 * Source-row locator a row carries explicitly (search hits: the API `locator`), as
 * `fields.reviewCollection` / `reviewKind` / `reviewPointer`; null when the row has none.
 */
function carriedLocator(row: GridRow): { collection: string; kind: string; pointer: string } | null {
  const collection = row.fields.reviewCollection;
  const pointer = row.fields.reviewPointer;
  if (
    typeof collection !== "string" ||
    !collection ||
    typeof pointer !== "string" ||
    !pointer.startsWith("/")
  )
    return null;
  const kind = typeof row.fields.reviewKind === "string" ? row.fields.reviewKind : "";
  if (collection === "artifacts" && !kind) return null;
  return { collection, kind, pointer };
}

/** Bookmark API target (`source` alias + JSON pointer) for a grid row, or null when unknown. */
export function bookmarkTarget(row: GridRow): { source: string; pointer: string } | null {
  const carried = carriedLocator(row);
  if (carried) {
    return {
      source: carried.collection === "artifacts" ? `artifacts:${carried.kind}` : carried.collection,
      pointer: carried.pointer,
    };
  }
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
  /** Rows the mark did not apply to (no source record), each with its reason. */
  skipped?: SkippedRow[];
  /** "clear-review" only: the status the first row went back to (its previous state). */
  restored?: ReviewSnapshot;
}

/** Toast suffix that tells the analyst a mark went to the case.json fallback, not the case DB. */
export const BOOKMARK_FALLBACK_NOTICE = "케이스 DB를 만들 수 없어 case.json 북마크에 저장했습니다";

export function storeNotice(result: ApplyResult): string {
  return result.store === "bookmarks" ? ` (${BOOKMARK_FALLBACK_NOTICE})` : "";
}

// ---- case DB handle (ensure once per run) ----------------------------------

const caseDbHandles = new Map<string, Promise<CaseDbHandle | null>>();
/** Runs whose `/case-db/ensure` is in flight (only these say "케이스 DB 준비 중…"). */
const preparingRuns = new Set<string>();

/** Forget cached handles (tests; a run re-import). */
export function resetCaseDbHandles(): void {
  caseDbHandles.clear();
  preparingRuns.clear();
  resetReviewUndo();
}

/** Shown while POST /case-db/ensure is still running (first import can take minutes). */
export const CASE_DB_PREPARING_NOTICE = "케이스 DB 준비 중… 완료되면 표시가 적용됩니다";

/** Immediate feedback for a mark that waits on the case DB: one polite sentence + the status-bar notice. */
function notifyPreparing(): void {
  announce(CASE_DB_PREPARING_NOTICE);
  useAppStore.getState().showNotice(CASE_DB_PREPARING_NOTICE);
}

/** The preparing toast goes once the case DB answered: one toast per mark, not two (review P2). */
function clearPreparing(): void {
  const toasts = useToastStore.getState();
  for (const toast of toasts.toasts) if (toast.text === CASE_DB_PREPARING_NOTICE) toasts.dismiss(toast.id);
}

/**
 * The handle the run itself reports (`GET /api/runs/{id}` `case_db_ready`, r7 L4 C-G13): an
 * already-imported case DB needs no `/case-db/ensure` round trip and no "준비 중" toast. Any error
 * (older server, network) falls back to ensure.
 */
function readyHandle(runId: string): Promise<CaseDbHandle | null> {
  return getRun(runId).then(
    (run) => (run.case_db_ready && run.case_db?.database && run.case_db.case_id ? run.case_db : null),
    () => null,
  );
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
  const pending = readyHandle(runId)
    .then((ready) => {
      if (ready) return ready;
      preparingRuns.add(runId);
      notifyPreparing();
      return ensureCaseDb(runId);
    })
    .then(
      (handle) => {
        preparingRuns.delete(runId);
        clearPreparing();
        return handle;
      },
      (error: unknown) => {
        caseDbHandles.delete(runId);
        preparingRuns.delete(runId);
        clearPreparing();
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
  if (action === "clear-review") return clearToPrevious(runId, rows);
  // Judgement marks are undoable: the rows' state before the mark is taken now (before the
  // optimistic patch reaches the server) and kept as one unit for "실행 취소" / Ctrl+Z.
  const before = UNDOABLE_ACTIONS.has(action) ? snapshotEntries(runId, rows) : null;
  const result = await applyBody(runId, rows, markBody(action, options.tag), caseDbMark(action, options.tag));
  if (before) {
    const pushes = STATUS_MARKS.has(action);
    for (const entry of before) {
      rememberWritten(entry, afterMark(action, entry.before));
      if (pushes) {
        pushPrior(entry.key, entry.before);
        entry.stack = "push";
      }
    }
    recordUndo(runId, action, before);
  }
  return result;
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

/** A row a mark could not apply to, with the Korean reason shown to the analyst. */
export interface SkippedRow {
  row: GridRow;
  reason: string;
}

/** Why a row has no review target (shown per row when a batch skips it). */
export const NO_SOURCE_ROW_REASON = "출처 위치(원본 레코드)를 알 수 없는 행입니다";

/** Rows a review mark can target (case-db id or run-output locator), and the rest with a reason. */
export function partitionReviewRows(rows: GridRow[]): { targetable: GridRow[]; skipped: SkippedRow[] } {
  const targetable: GridRow[] = [];
  const skipped: SkippedRow[] = [];
  for (const row of rows) {
    if (reviewTargetOf(row)) targetable.push(row);
    else skipped.push({ row, reason: NO_SOURCE_ROW_REASON });
  }
  return { targetable, skipped };
}

/** Toast suffix naming the skipped rows ("… 2건은 건너뜀: 제목1, 제목2"). */
export function skippedNotice(skipped: readonly SkippedRow[]): string {
  if (skipped.length === 0) return "";
  const names = skipped
    .slice(0, 3)
    .map((item) => item.row.title || item.row.rowKey)
    .join(", ");
  const more = skipped.length > 3 ? ` 외 ${skipped.length - 3}건` : "";
  return ` 출처 위치(원본 레코드)를 알 수 없는 ${skipped.length}건은 건너뛰었습니다: ${names}${more}.`;
}

async function applyBody(
  runId: string,
  allRows: GridRow[],
  body: MarkPayload,
  mark: ReviewMarkBody,
): Promise<ApplyResult> {
  // Rows without a source record (aggregates, derived rows) are skipped with a note; the
  // mark still applies to every row that has one.
  const { targetable: rows, skipped } = partitionReviewRows(allRows);
  if (rows.length === 0) {
    throw new Error(
      `출처 위치를 알 수 없는 행이 ${allRows.length}건 있습니다(원본 레코드 없음, 집계·파생 행).`,
    );
  }
  const targets = rows.map(reviewTargetOf);
  // Queue on the (shared, cached) ensure promise: a mark made while the case DB is still being
  // prepared is applied when it resolves, never dropped; the analyst hears that right away.
  const pending = caseDbHandle(runId);
  // A mark queued behind an ensure still in flight hears the notice too.
  if (preparingRuns.has(runId)) notifyPreparing();
  const handle = await pending;
  let store: ReviewStore;
  if (handle) {
    // The review author (AXIOM E3) rides on every mark: the typed name, else the case's 담당자,
    // else "" (the server keeps its own attribution; never the old "web-ui" default, T-036).
    const authored: ReviewMarkBody = { ...mark, reviewer: currentReviewer(runId) };
    await postReviewBatch(handle, targets as ReviewBatchTarget[], authored, runId);
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
  return skipped.length ? { applied: rows.length, store, skipped } : { applied: rows.length, store };
}

// ---- review tools (AXIOM E3) ---------------------------------------------

/**
 * The run's case DB handle (POST /case-db/ensure once per run, shared with the marks above);
 * null when the server says no case DB can be created for this run.
 */
export function ensureRunCaseDb(runId: string): Promise<CaseDbHandle | null> {
  const pending = caseDbHandle(runId);
  if (preparingRuns.has(runId)) notifyPreparing();
  return pending;
}

/** Tell the listeners (review-map / review-counts invalidation) that marks of the run changed. */
export function notifyReviewApplied(runId: string): void {
  for (const listener of listeners) listener(runId, "case-db");
}

// ---- previous state · 실행 취소 (r8 T-036) ----------------------------------

/** A row's judgement as the case DB stores it: status (`unreviewed` when none) + report flag. */
export interface ReviewSnapshot {
  status: "unreviewed" | "relevant" | "needs-review" | "excluded";
  include: boolean;
}

const STATUS_VALUES = new Set(["unreviewed", "relevant", "needs-review", "excluded"]);

/** Marks that set a status (their un-press goes back to the state before them). */
const STATUS_MARKS: ReadonlySet<BatchAction> = new Set(["relevant", "needs-review", "excluded"]);
/** Judgement marks "실행 취소" / Ctrl+Z can take back (tags, notes and extracts are not judgements). */
const UNDOABLE_ACTIONS: ReadonlySet<BatchAction> = new Set([
  "relevant",
  "needs-review",
  "excluded",
  "include-in-report",
  "remove-from-report",
]);

/** Whether a mark is a judgement "실행 취소" can take back (an un-press included). */
export function isUndoableAction(action: BatchAction): boolean {
  return UNDOABLE_ACTIONS.has(action) || action === "clear-review";
}

/** The judgement a grid row shows (the review-map overlay already applied). */
export function snapshotOf(row: GridRow): ReviewSnapshot {
  const status = row.reviewStatus;
  return {
    status:
      status === "relevant" || status === "needs-review" || status === "excluded" ? status : "unreviewed",
    include: row.fields.includeInReport === true || status === "include-in-report",
  };
}

/** Optimistic row transform back to a stored judgement (un-press, 실행 취소). */
export function optimisticRestore(snapshot: ReviewSnapshot): (row: GridRow) => GridRow {
  return (row) => ({
    ...row,
    reviewStatus:
      snapshot.status !== "unreviewed" ? snapshot.status : snapshot.include ? "include-in-report" : null,
    fields: { ...row.fields, includeInReport: snapshot.include },
  });
}

/** Per row (run + review target): the judgements before each status mark of this session. */
const priorStacks = new Map<string, ReviewSnapshot[]>();
const PRIOR_DEPTH = 20;

function priorKey(runId: string, row: GridRow): string {
  return `${runId}|${JSON.stringify(reviewTargetOf(row))}`;
}

function pushPrior(key: string, snapshot: ReviewSnapshot): void {
  const stack = priorStacks.get(key) ?? [];
  stack.push(snapshot);
  if (stack.length > PRIOR_DEPTH) stack.shift();
  priorStacks.set(key, stack);
}

function popPrior(key: string): ReviewSnapshot | undefined {
  const stack = priorStacks.get(key);
  const top = stack?.pop();
  if (stack && stack.length === 0) priorStacks.delete(key);
  return top;
}

/** The previous judgement this session knows for a row (no network; the optimistic un-press). */
export function knownPrevious(runId: string, row: GridRow): ReviewSnapshot | undefined {
  return priorStacks.get(priorKey(runId, row))?.at(-1);
}

/** Rows looked up in the case-DB history when this session has no previous state for them. */
export const HISTORY_LOOKUP_MAX = 20;

interface StatusChange {
  before: string;
  after: string;
}

/**
 * The newest status change that was not taken back, from status changes listed newest first. A
 * change that exactly reverses the older one next to it (an un-press: 제외 → 관련 after 관련 → 제외)
 * cancels it, the way an undo cancels the mark it undoes; pairs nest. Without this, un-pressing
 * after a reload alternates between the last two statuses and never reaches 미검토 (T-036).
 */
export function newestStandingChange(changes: readonly StatusChange[]): StatusChange | null {
  const standing: StatusChange[] = [];
  for (const change of changes) {
    const newer = standing.at(-1);
    if (newer && newer.before === change.after && newer.after === change.before) standing.pop();
    else standing.push(change);
  }
  return standing[0] ?? null;
}

/**
 * The status a row had before its current one, from the case-DB history (newest first): the
 * `status_before` of the newest status change that was not taken back. Null when unknown (no case
 * DB, no history, a row without a run-output locator, any error).
 */
async function historyPrevious(runId: string, row: GridRow): Promise<ReviewSnapshot["status"] | null> {
  if (isCaseDbRow(row)) return null;
  const target = reviewLocatorTarget(row);
  if (!target) return null;
  try {
    const { entries } = await getReviewHistory(runId, target);
    const changes = (entries ?? [])
      .map((entry) => ({
        before: entry.status_before || "unreviewed",
        after: entry.status_after || "unreviewed",
      }))
      .filter((change) => change.before !== change.after);
    const change = newestStandingChange(changes);
    if (!change) return null;
    return STATUS_VALUES.has(change.before) ? (change.before as ReviewSnapshot["status"]) : null;
  } catch {
    return null;
  }
}

interface UndoEntry {
  row: GridRow;
  key: string;
  before: ReviewSnapshot;
  /** What the mark did to the row's previous-state stack (undone with it). */
  stack: "push" | "pop" | "none";
  popped?: ReviewSnapshot;
}

/**
 * The judgement this tab last wrote per row (run + review target). A row object handed to a mark
 * can lag behind (the viewer's row is not the grid's optimistic copy), so a mark made right after
 * another one still takes the right "before" (QA-065: 관련 있음 → 제외 → 해제 = 관련 있음). Only while
 * the row still shows what it showed when the write was made: a row that shows something else was
 * changed elsewhere (the 검토 목록 holds the same item under another key, another tab, a refetch)
 * and its own state wins over the stale write (T-036).
 */
const writtenStates = new Map<string, { seen: ReviewSnapshot; state: ReviewSnapshot }>();

function sameSnapshot(a: ReviewSnapshot, b: ReviewSnapshot): boolean {
  return a.status === b.status && a.include === b.include;
}

function rememberWritten(entry: { key: string; row: GridRow }, state: ReviewSnapshot): void {
  writtenStates.set(entry.key, { seen: snapshotOf(entry.row), state });
}

/** A row's judgement as this tab knows it: its last write while the row lags, else the row. */
function currentJudgement(key: string, row: GridRow): ReviewSnapshot {
  const shown = snapshotOf(row);
  const written = writtenStates.get(key);
  return written && sameSnapshot(written.seen, shown) ? written.state : shown;
}

function afterMark(action: BatchAction, before: ReviewSnapshot): ReviewSnapshot {
  switch (action) {
    case "relevant":
    case "needs-review":
      return { status: action, include: before.include };
    case "excluded":
      return { status: "excluded", include: false };
    case "include-in-report":
      return { status: before.status, include: true };
    case "remove-from-report":
      return { status: before.status, include: false };
    default:
      return before;
  }
}

function snapshotEntries(runId: string, rows: GridRow[]): UndoEntry[] {
  return partitionReviewRows(rows).targetable.map((row) => {
    const key = priorKey(runId, row);
    return { row, key, before: currentJudgement(key, row), stack: "none" as const };
  });
}

type SnapshotGroups = Map<string, { snapshot: ReviewSnapshot; withReport: boolean; rows: GridRow[] }>;

/** `withReport`: the batch sends the report flag too (else the status only; the flag stays). */
function addToGroup(groups: SnapshotGroups, snapshot: ReviewSnapshot, row: GridRow, withReport = true): void {
  const key = withReport ? `${snapshot.status}|${snapshot.include}` : `${snapshot.status}|-`;
  const group = groups.get(key) ?? { snapshot, withReport, rows: [] };
  group.rows.push(row);
  groups.set(key, group);
}

/** Apply each distinct judgement to its rows (one review-batch per group). */
async function applySnapshots(runId: string, groups: SnapshotGroups): Promise<ApplyResult> {
  let applied = 0;
  let store: ReviewStore | undefined;
  for (const { snapshot, withReport, rows } of groups.values()) {
    const body: MarkPayload = { review_status: snapshot.status, status: snapshot.status };
    const mark: ReviewMarkBody = { status: snapshot.status };
    if (withReport) {
      body.include_in_report = snapshot.include;
      mark.include_in_report = snapshot.include;
    }
    const result = await applyBody(runId, rows, body, mark);
    applied += result.applied;
    store = result.store;
  }
  return store ? { applied, store } : { applied };
}

/**
 * The report flag an un-press leaves (T-036): the flag from before the status mark only when that
 * mark is what changed it (제외 clears it) and nothing changed it since; a later "보고서 포함" stays.
 */
function unpressedInclude(current: ReviewSnapshot, prior: ReviewSnapshot): boolean {
  const leftByMark = current.status === "excluded" ? false : prior.include;
  return current.include === leftByMark ? prior.include : current.include;
}

/**
 * Un-press of a status toggle (GAP-024): every row goes back to its previous judgement — this
 * session's stack (status; the report flag only when the un-pressed mark changed it), else its
 * case-DB history (status), else `unreviewed`.
 * Rows that go back to different states are posted as one batch per state; the whole un-press
 * is one undo unit.
 */
async function clearToPrevious(runId: string, allRows: GridRow[]): Promise<ApplyResult> {
  const { targetable, skipped } = partitionReviewRows(allRows);
  if (targetable.length === 0) {
    return applyBody(runId, allRows, markBody("clear-review"), caseDbMark("clear-review"));
  }
  const entries = snapshotEntries(runId, targetable);
  const lookups = entries.filter((entry) => !priorStacks.get(entry.key)?.length);
  const fromHistory = new Map<UndoEntry, ReviewSnapshot["status"] | null>();
  if (lookups.length <= HISTORY_LOOKUP_MAX) {
    const found = await Promise.all(lookups.map((entry) => historyPrevious(runId, entry.row)));
    lookups.forEach((entry, at) => {
      fromHistory.set(entry, found[at] ?? null);
    });
  }
  const groups: SnapshotGroups = new Map();
  const restored: { entry: UndoEntry; snapshot: ReviewSnapshot }[] = [];
  let first: ReviewSnapshot | undefined;
  for (const entry of entries) {
    const known = priorStacks.get(entry.key)?.at(-1);
    // History knows the status only: the report flag stays as it is.
    const snapshot: ReviewSnapshot = known
      ? { status: known.status, include: unpressedInclude(entry.before, known) }
      : { status: fromHistory.get(entry) ?? "unreviewed", include: entry.before.include };
    first ??= snapshot;
    restored.push({ entry, snapshot });
    // The flag is sent only where the un-press changes it (never a stale copy of it).
    addToGroup(groups, snapshot, entry.row, snapshot.include !== entry.before.include);
  }
  const result = await applySnapshots(runId, groups);
  for (const { entry, snapshot } of restored) rememberWritten(entry, snapshot);
  for (const entry of entries) {
    if (priorStacks.get(entry.key)?.length) {
      entry.popped = popPrior(entry.key);
      entry.stack = "pop";
    }
  }
  recordUndo(runId, "clear-review", entries);
  return {
    ...result,
    ...(skipped.length ? { skipped } : {}),
    ...(first ? { restored: first } : {}),
  };
}

/** One mark (n rows) as "실행 취소" takes it back: all rows together. */
export interface UndoUnit {
  runId: string;
  action: BatchAction;
  entries: UndoEntry[];
}

/** The undo stack lives in memory: a reload forgets it (UNDO_SCOPE_NOTICE says so). */
const undoStack: UndoUnit[] = [];
const UNDO_DEPTH = 20;

export const UNDO_LABEL = "실행 취소";
/** Why there is nothing to undo (the stack is per tab and is lost on reload). */
export const UNDO_SCOPE_NOTICE = "방금 한 표시만 되돌릴 수 있습니다";
export const UNDO_NOTHING_REASON = `되돌릴 표시가 없습니다. ${UNDO_SCOPE_NOTICE}(새로고침하면 지워집니다)`;
/** `ToastAction.key` of the undo button (one at a time: a newer mark replaces the older button). */
export const UNDO_TOAST_KEY = "review-undo";

function recordUndo(runId: string, action: BatchAction, entries: UndoEntry[]): void {
  if (entries.length === 0) return;
  undoStack.push({ runId, action, entries });
  if (undoStack.length > UNDO_DEPTH) undoStack.shift();
  // The older undo button would take back a mark that is no longer the last one.
  useToastStore.getState().dismissActionKey(UNDO_TOAST_KEY);
}

/** The newest undoable mark of `runId` (null when there is none). */
export function lastUndo(runId: string | null): UndoUnit | null {
  if (!runId) return null;
  for (let at = undoStack.length - 1; at >= 0; at -= 1) {
    const unit = undoStack[at];
    if (unit?.runId === runId) return unit;
  }
  return null;
}

/** Forget the undo stack and the previous-state stacks (tests; a run re-import). */
export function resetReviewUndo(): void {
  undoStack.length = 0;
  undoQueues.clear();
  priorStacks.clear();
  writtenStates.clear();
}

export interface UndoResult {
  applied: number;
  /** Label of the mark that was taken back ("제외", "선별 해제", …). */
  label: string;
  /** Row keys and the judgement each went back to (for the optimistic patch). */
  rows: { rowKey: string; before: ReviewSnapshot }[];
  store?: ReviewStore;
}

/** Per run: the undo write in flight (the next undo waits for it, in stack order). */
const undoQueues = new Map<string, Promise<unknown>>();

/**
 * Take back the newest mark of `runId` as one unit (every row of a batch together): each row goes
 * back to its judgement before the mark, through the same review-batch request. Throws
 * UNDO_NOTHING_REASON when there is nothing to undo. The unit leaves the stack at once, so a second
 * Ctrl+Z (or the toast button) before the first one's answer takes the next older unit, written
 * after the first; on failure the unit goes back where it was (T-036).
 */
export function undoLastReview(runId: string | null): Promise<UndoResult> {
  const unit = lastUndo(runId);
  if (!unit || !runId) return Promise.reject(new Error(UNDO_NOTHING_REASON));
  const at = undoStack.indexOf(unit);
  undoStack.splice(at, 1);
  useToastStore.getState().dismissActionKey(UNDO_TOAST_KEY);
  // An earlier undo that failed fails this one too (its unit goes back on top, this one below it).
  const write = (undoQueues.get(runId) ?? Promise.resolve()).then(() => writeUndo(runId, unit));
  undoQueues.set(runId, write);
  const settle = () => {
    if (undoQueues.get(runId) === write) undoQueues.delete(runId);
  };
  return write.then(
    (result) => {
      settle();
      return result;
    },
    (error: unknown) => {
      settle();
      undoStack.splice(Math.min(at, undoStack.length), 0, unit);
      throw error;
    },
  );
}

async function writeUndo(runId: string, unit: UndoUnit): Promise<UndoResult> {
  const groups: SnapshotGroups = new Map();
  for (const entry of unit.entries) addToGroup(groups, entry.before, entry.row);
  const result = await applySnapshots(runId, groups);
  for (const entry of unit.entries) {
    rememberWritten(entry, entry.before);
    if (entry.stack === "push") popPrior(entry.key);
    else if (entry.stack === "pop" && entry.popped) pushPrior(entry.key, entry.popped);
  }
  return {
    applied: result.applied,
    label: MARK_LABELS[unit.action],
    rows: unit.entries.map((entry) => ({ rowKey: entry.row.rowKey, before: entry.before })),
    ...(result.store ? { store: result.store } : {}),
  };
}

/** Sentence after a successful undo. */
export function undoneNotice(result: UndoResult): string {
  return `${UNDO_LABEL}: ${result.label} ${result.applied}건을 이전 상태로 되돌렸습니다.`;
}

/** The shell command that undoes (Ctrl+Z, the toast button, the palette): commands/review.ts. */
export const UNDO_COMMAND_ID = "review.undo";

/**
 * The "실행 취소" toast button for the newest mark of `runId` (undefined when there is none). It
 * runs the same review.undo command as Ctrl+Z (optimistic patch, notice, errors announced).
 */
export function undoToastAction(runId: string | null): ToastAction | undefined {
  if (!lastUndo(runId)) return undefined;
  return {
    label: UNDO_LABEL,
    run: () => void runCommand(UNDO_COMMAND_ID),
    key: UNDO_TOAST_KEY,
    shortcut: KEY_MAP.undoReview,
  };
}
