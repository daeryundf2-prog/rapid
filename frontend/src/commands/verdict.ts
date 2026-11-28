/**
 * The verdict key flow (design-viewer-keys F17): which rows R / I / X / B act on, what happens
 * after a verdict, and Z.
 *
 * One function, `reviewScope()`, answers "which rows": two or more selected rows → the selected
 * rows the list shows now ("선택 n건"; selected rows the filters hide are left out and named, "숨은
 * 선택 m건 제외"); otherwise the viewer's row, which follows the grid's focused row ("08:02:48 행").
 * The status-bar hint, the announcement and the write all read it, so a key never marks rows other
 * than the ones the screen named.
 *
 * After a verdict the list moves on (setting: 다음 행 (default) · 다음 미판정 행 · 그대로,
 * persisted), the result is announced politely ("관련 있음 3건 · Z 되돌리기"), and Z puts the
 * last batch back to its previous status / report flag / tags exactly.
 */

import type { QueryClient } from "@tanstack/react-query";
import { create } from "zustand";
import { announce } from "../a11y";
import type { GridRow } from "../contracts/collection";
import { type CommandContext, KEY_MAP } from "../contracts/command";
import type { MarkAction } from "../contracts/viewer";
import { baseName, currentTimezone } from "../features/grid/columns/common";
import {
  type ApplyResult,
  applyReviewAction,
  type BatchAction,
  optimisticPatch,
  restoredPatch,
  restoreReviewState,
  reviewTargetOf,
  storeNotice,
} from "../features/grid/reviewActions";
import { currentRowSource, type RowFocusResult } from "../features/review/rowSource";
import { targetAsGridRow } from "../features/viewer/citation";
import { readStored, writeStored } from "../state/storage";
import { useAppStore } from "../state/store";
import { formatTimestamp } from "../utils/time";
import { NO_RUN_REASON } from "./reasons";
import { getCommand } from "./registry";

export const NO_ROW_REASON = "표시할 행이 없습니다. 그리드에서 행을 선택하세요";

// --- scope -------------------------------------------------------------------

/** Two or more checked rows make the selection the scope (one checked row is the row itself). */
export const SELECTION_SCOPE_MIN = 2;

export interface ReviewScope {
  kind: "selection" | "row" | "none";
  rows: GridRow[];
  /** "선택 3건" · "08:02:48 행" · "'History' 행"; "" when there is no row. */
  label: string;
  /** Selected rows left out because the list does not show them (filtered out, not loaded). */
  hidden: number;
  runId: string | null;
  /**
   * The rows' previous review state is known (grid rows): Z can restore it. A viewer target
   * reached through the viewer's own history has no grid row, so its old state is unknown.
   */
  restorable: boolean;
}

const NO_SCOPE: ReviewScope = {
  kind: "none",
  rows: [],
  label: "",
  hidden: 0,
  runId: null,
  restorable: false,
};

/** "숨은 선택 2건 제외": what a selection verdict left out. */
export function hiddenSelectionText(hidden: number): string {
  return hidden > 0 ? `숨은 선택 ${hidden.toLocaleString("ko-KR")}건 제외` : "";
}

/** "08:02:48 행" from the row time in the display zone, else the row's short name. */
export function rowScopeLabel(row: GridRow, tz: string = currentTimezone()): string {
  if (row.timestamp) {
    const text = formatTimestamp(row.timestamp, tz);
    const clock = /\d{2}:\d{2}:\d{2}/.exec(text)?.[0];
    if (clock) return `${clock} 행`;
  }
  const name = baseName(row.sourcePath ?? row.title ?? row.ref.locator).trim();
  const short = name.length > 24 ? `${name.slice(0, 23)}…` : name;
  return `'${short}' 행`;
}

/** The rows R / I / X / B act on right now (see the module comment). */
export function reviewScope(ctx?: Pick<CommandContext, "selectedRowKeys" | "runId">): ReviewScope {
  const state = useAppStore.getState();
  const selectedKeys = ctx?.selectedRowKeys ?? state.selectedRowKeys;
  const runId = ctx?.runId ?? state.route.runId;
  if (selectedKeys.length >= SELECTION_SCOPE_MIN) {
    // Selection survives filter changes: only the selected rows on screen are judged (review P2-1).
    const source = currentRowSource();
    const loaded = source?.getSelectedRows() ?? [];
    const rows = source?.isShown ? loaded.filter((row) => source.isShown?.(row.rowKey)) : loaded;
    const hidden = Math.max(0, selectedKeys.length - rows.length);
    if (rows.length >= SELECTION_SCOPE_MIN || (rows.length > 0 && hidden > 0)) {
      const count = `선택 ${rows.length.toLocaleString("ko-KR")}건`;
      return {
        kind: "selection",
        rows,
        label: hidden > 0 ? `${count} · ${hiddenSelectionText(hidden)}` : count,
        hidden,
        runId,
        restorable: true,
      };
    }
  }
  const target = state.viewerTarget;
  if (!target) {
    // No viewer target yet (the shell has not mirrored the grid's focus): the list's own cursor row.
    const focused = currentRowSource()?.getFocusedRow?.();
    if (!focused || !runId) return NO_SCOPE;
    return {
      kind: "row",
      rows: [focused],
      label: rowScopeLabel(focused),
      hidden: 0,
      runId,
      restorable: true,
    };
  }
  const known = state.viewerRow;
  const row = known ?? targetAsGridRow(target);
  return {
    kind: "row",
    rows: [row],
    label: rowScopeLabel(row),
    hidden: 0,
    runId: target.runId,
    restorable: !!known,
  };
}

export const NO_LOCATION_REASON = "출처 위치를 알 수 없는 행은 표시할 수 없습니다";

/** A row the case DB (or the case.json fallback) cannot locate cannot carry a verdict. */
export function verdictRowReason(row: GridRow, action: MarkAction): string | undefined {
  if (reviewTargetOf(row)) return undefined;
  return action === "bookmark" ? "북마크할 수 있는 위치 정보가 없는 행입니다" : NO_LOCATION_REASON;
}

// --- after a verdict ---------------------------------------------------------

export type AdvanceMode = "next" | "next-unreviewed" | "stay";
export const ADVANCE_MODES: readonly AdvanceMode[] = ["next", "next-unreviewed", "stay"];
export const ADVANCE_LABELS: Record<AdvanceMode, string> = {
  next: "다음 행",
  "next-unreviewed": "다음 미판정 행",
  stay: "그대로",
};
export const ADVANCE_STORAGE_KEY = "rapidtriage.verdictAdvance";

function readAdvance(): AdvanceMode {
  const stored = readStored(ADVANCE_STORAGE_KEY);
  return ADVANCE_MODES.includes(stored as AdvanceMode) ? (stored as AdvanceMode) : "next";
}

interface VerdictPrefs {
  advance: AdvanceMode;
  setAdvance: (mode: AdvanceMode) => void;
}

export const useVerdictPrefs = create<VerdictPrefs>((set) => ({
  advance: readAdvance(),
  setAdvance: (advance) => {
    writeStored(ADVANCE_STORAGE_KEY, advance);
    set({ advance });
  },
}));

/** Verdicts that move the list on (tags and notes stay on the row). */
const ADVANCING: ReadonlySet<BatchAction> = new Set<BatchAction>([
  "relevant",
  "needs-review",
  "excluded",
  "bookmark",
  "include-in-report",
]);

/** DOM focus is in the viewer (or its drawer): moving the list must not pull it out. */
export function focusInViewer(): boolean {
  const active = typeof document === "undefined" ? null : document.activeElement;
  return active instanceof Element && active.closest(".viewer, #viewer") !== null;
}

/**
 * Move the list after a verdict on `scope`. Runs BEFORE the optimistic patch: the next row is
 * picked by key from the list as it was, so judged rows leaving a filtered list cannot shift the
 * cursor past a row (review P1-2; the grid then follows that key).
 */
function advanceAfter(
  scope: ReviewScope,
  mode: AdvanceMode,
  selectedKeys: readonly string[],
): RowFocusResult {
  if (mode === "stay") return "moved";
  const source = currentRowSource();
  if (!source?.moveFocus) return "moved";
  // A judged selection is done: the next key acts on the next row, not the same batch again.
  // Selected rows the filters hid stay selected (they were not judged).
  if (scope.kind === "selection") {
    const judged = new Set(scope.rows.map((row) => row.rowKey));
    const rest = selectedKeys.filter((key) => !judged.has(key));
    if (rest.length && source.setSelection) source.setSelection(rest);
    else source.clearSelection?.();
  }
  return source.moveFocus({
    after: scope.rows.map((row) => row.rowKey),
    unreviewed: mode === "next-unreviewed",
    domFocus: !focusInViewer(),
  });
}

/** Said when the list stopped at its loaded end (more rows exist below). */
export const UNLOADED_END = "불러온 마지막 행 — 아래로 스크롤해 더 불러오기";

/** Why the list did not move after a verdict ("" when it moved). */
export function advanceStopText(result: RowFocusResult, mode: AdvanceMode): string {
  if (result === "moved") return "";
  if (mode === "next-unreviewed") {
    return result === "unloaded"
      ? "불러온 행 중 미판정 없음 — 아래로 스크롤해 더 불러오기"
      : "다음 미판정 행 없음";
  }
  return result === "unloaded" ? UNLOADED_END : "마지막 행";
}

// --- verdict labels ----------------------------------------------------------

const VERDICT_LABELS: Partial<Record<BatchAction, string>> = {
  relevant: "관련 있음",
  "needs-review": "재검토",
  excluded: "제외",
  bookmark: "북마크",
  "include-in-report": "보고서 포함",
  "clear-review": "판정 해제",
  "remove-from-report": "보고서 포함 해제",
};

export function verdictLabel(action: BatchAction, tag?: string): string {
  if (action === "tag") return tag ? `태그 '${tag}'` : "태그";
  return VERDICT_LABELS[action] ?? action;
}

const VERDICT_KEYS: Partial<Record<string, string>> = {
  relevant: KEY_MAP.markRelevant,
  "needs-review": KEY_MAP.markNeedsReview,
  excluded: KEY_MAP.markExcluded,
  bookmark: KEY_MAP.bookmark,
};

/** The key of a verdict (R / I / X / B): the registered review.mark.* key, else KEY_MAP's. */
export function verdictShortcut(action: string): string | undefined {
  return getCommand(`review.mark.${action}`)?.shortcut ?? VERDICT_KEYS[action];
}

// --- undo stack --------------------------------------------------------------

interface UndoEntry {
  runId: string;
  action: BatchAction;
  label: string;
  /** Row snapshots taken before the verdict. */
  before: GridRow[];
  /** The list's focused row when the verdict was given (Z returns there). */
  focusKey: string | null;
}

/** Last verdict batches, newest last; Z pops one. */
export const UNDO_LIMIT = 20;

interface UndoState {
  entries: UndoEntry[];
  push: (entry: UndoEntry) => void;
  pop: () => UndoEntry | undefined;
  clear: () => void;
}

export const useVerdictUndo = create<UndoState>((set, get) => ({
  entries: [],
  push: (entry) => set({ entries: [...get().entries, entry].slice(-UNDO_LIMIT) }),
  pop: () => {
    const entries = get().entries;
    const last = entries.at(-1);
    if (last) set({ entries: entries.slice(0, -1) });
    return last;
  },
  clear: () => set({ entries: [] }),
}));

export const NOTHING_TO_UNDO_REASON = "되돌릴 판정이 없습니다";

/** Why Z cannot run: nothing recorded for the open run. */
export function undoDisabledReason(runId: string | null): string | undefined {
  if (!runId) return NO_RUN_REASON;
  const last = useVerdictUndo.getState().entries.at(-1);
  return last && last.runId === runId ? undefined : NOTHING_TO_UNDO_REASON;
}

function snapshot(row: GridRow): GridRow {
  return { ...row, tags: [...row.tags], fields: { ...row.fields } };
}

async function refresh(queryClient: QueryClient | null, runId: string): Promise<void> {
  await queryClient?.invalidateQueries({ predicate: (query) => query.queryKey.includes(runId) });
}

function tell(text: string): void {
  announce(text);
  useAppStore.getState().showNotice(text);
}

// --- running -----------------------------------------------------------------

/** Why a verdict key cannot run now (no run, no row, a row without a review location). */
export function verdictDisabledReason(
  action: MarkAction,
  ctx: Pick<CommandContext, "runId" | "selectedRowKeys">,
): string | undefined {
  if (!ctx.runId) return NO_RUN_REASON;
  const scope = reviewScope(ctx);
  if (scope.kind === "none") return NO_ROW_REASON;
  for (const row of scope.rows) {
    const reason = verdictRowReason(row, action);
    if (reason) return scope.kind === "selection" ? `선택한 행 중 ${reason}` : reason;
  }
  return undefined;
}

export interface VerdictResult {
  scope: ReviewScope;
  /** The announced sentence. */
  text: string;
}

/**
 * Apply `action` to `reviewScope()` — the one write path of the verdict keys, the batch bar, the
 * row menu and the viewer header buttons. Optimistic on the list, rolled back on failure.
 */
export async function runVerdict(
  queryClient: QueryClient | null,
  action: BatchAction,
  options: { tag?: string; advance?: boolean; ctx?: Pick<CommandContext, "selectedRowKeys" | "runId"> } = {},
): Promise<VerdictResult> {
  const scope = reviewScope(options.ctx);
  if (scope.kind === "none" || !scope.runId) throw new Error(NO_ROW_REASON);
  const runId = scope.runId;
  const source = currentRowSource();
  const before = scope.rows.map(snapshot);
  const focusKey =
    scope.kind === "row"
      ? (scope.rows[0]?.rowKey ?? null)
      : (source?.getFocusedRow?.()?.rowKey ?? useAppStore.getState().focusedRowKey);
  const keys = scope.rows.map((row) => row.rowKey);
  const selectedKeys = [...(options.ctx?.selectedRowKeys ?? useAppStore.getState().selectedRowKeys)];
  const mode = useVerdictPrefs.getState().advance;
  const moves = options.advance !== false && ADVANCING.has(action);
  // Pick the next row by key before the patch can take judged rows out of the list (P1-2).
  const moved: RowFocusResult = moves ? advanceAfter(scope, mode, selectedKeys) : "moved";
  const rollback = scope.restorable
    ? (source?.patchRows?.(keys, optimisticPatch(action, options.tag)) ?? (() => {}))
    : () => {};
  let result: ApplyResult;
  try {
    result = await applyReviewAction(runId, scope.rows, action, options.tag ? { tag: options.tag } : {});
  } catch (error) {
    rollback();
    // The write failed: the selection and the cursor go back too, so the analyst retries the same
    // rows (review P3-3).
    if (moves && mode !== "stay") {
      if (scope.kind === "selection") source?.setSelection?.(selectedKeys);
      if (focusKey) source?.moveFocus?.({ key: focusKey, domFocus: !focusInViewer() });
    }
    throw error;
  }
  if (scope.restorable) {
    useVerdictUndo
      .getState()
      .push({ runId, action, label: verdictLabel(action, options.tag), before, focusKey });
  }
  const count = scope.rows.length.toLocaleString("ko-KR");
  const tail = [
    scope.restorable ? "Z 되돌리기" : "이전 상태를 몰라 되돌릴 수 없음",
    hiddenSelectionText(scope.hidden),
    advanceStopText(moved, mode),
  ].filter(Boolean);
  const text = `${verdictLabel(action, options.tag)} ${count}건 · ${tail.join(" · ")}${storeNotice(result)}`;
  tell(text);
  await refresh(queryClient, runId);
  return { scope, text };
}

/** Z: put the last verdict batch back (status / report flag / tags as they were). */
export async function undoLastVerdict(queryClient: QueryClient | null): Promise<string> {
  const entry = useVerdictUndo.getState().pop();
  if (!entry) throw new Error(NOTHING_TO_UNDO_REASON);
  const source = currentRowSource();
  const byKey = new Map(entry.before.map((row) => [row.rowKey, row]));
  const rollback =
    source?.patchRows?.([...byKey.keys()], (row) => {
      const before = byKey.get(row.rowKey);
      return before ? restoredPatch(before, entry.action)(row) : row;
    }) ?? (() => {});
  try {
    await restoreReviewState(entry.runId, entry.before, entry.action);
  } catch (error) {
    rollback();
    // Keep the entry: the analyst can press Z again once the server answers.
    useVerdictUndo.getState().push(entry);
    throw error;
  }
  // Back to the row that was judged, so the right key can follow at once.
  if (entry.focusKey) source?.moveFocus?.({ key: entry.focusKey, domFocus: !focusInViewer() });
  const text = `되돌림: ${entry.label} ${entry.before.length.toLocaleString("ko-KR")}건`;
  tell(text);
  await refresh(queryClient, entry.runId);
  return text;
}
