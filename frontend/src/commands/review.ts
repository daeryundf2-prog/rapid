/**
 * Review keys (plan U5, design-viewer-keys F17): R / X / I / B give a verdict, Z undoes the last
 * one, J / K move the list's row (also while the viewer has focus), 1–9 tag keys.
 *
 * R / X / I / B act on `reviewScope()` (commands/verdict.ts): every selected row when two or
 * more are selected, else the viewer's row (which follows the grid's focused row). The batch bar,
 * the row menu and the viewer header buttons run these same commands, and the status-bar hint
 * names the same scope, so what is announced is what is marked.
 */

import type { QueryClient } from "@tanstack/react-query";
import { announce } from "../a11y";
import type { CaseTag } from "../api/reviewTools";
import { type Command, KEY_MAP } from "../contracts/command";
import type { MarkAction, ViewerTarget } from "../contracts/viewer";
import { applyReviewAction, type BatchAction, storeNotice } from "../features/grid/reviewActions";
import { currentRowSource } from "../features/review/rowSource";
import {
  resolveTagKey,
  TAG_KEY_DIGITS,
  tagKeyReason,
  toggleCaseTagOnContextRow,
} from "../features/review/tagKeys";
import { useCaseTagStore } from "../features/review/tagStore";
import { markDisabledReason, targetAsGridRow } from "../features/viewer/citation";
import { useAppStore } from "../state/store";
import { NO_RUN_REASON } from "./reasons";
import { relabelCommand } from "./registry";
import {
  ADVANCE_LABELS,
  ADVANCE_MODES,
  focusInViewer,
  NO_ROW_REASON,
  runVerdict,
  UNLOADED_END,
  undoDisabledReason,
  undoLastVerdict,
  useVerdictPrefs,
  verdictDisabledReason,
} from "./verdict";

export const PRIORITY_LEVELS = [1, 2, 3, 4, 5] as const;

export const priorityTag = (level: number) => `우선순위 ${level}`;

const MARKS: ReadonlyArray<{ action: MarkAction; label: string; shortcut?: string }> = [
  { action: "relevant", label: "관련 있음 표시", shortcut: KEY_MAP.markRelevant },
  { action: "excluded", label: "제외 표시", shortcut: KEY_MAP.markExcluded },
  { action: "needs-review", label: "재검토 표시", shortcut: KEY_MAP.markNeedsReview },
  { action: "bookmark", label: "북마크", shortcut: KEY_MAP.bookmark },
  { action: "include-in-report", label: "보고서 포함 표시" },
];

/** The row the tag keys act on: the viewer target (it follows grid focus). */
export function reviewTarget(): ViewerTarget | null {
  return useAppStore.getState().viewerTarget;
}

function reasonFor(action: MarkAction, runId: string | null): string | undefined {
  if (!runId) return NO_RUN_REASON;
  const target = reviewTarget();
  if (!target) return NO_ROW_REASON;
  return markDisabledReason(target, action);
}

export const NO_LIST_REASON = "행 목록이 열려 있지 않습니다";

/** J / K as commands: the grid handles them on its own rows; these serve focus elsewhere (the viewer). */
function rowStepCommand(step: 1 | -1): Command {
  return {
    id: step === 1 ? "navigate.row.next" : "navigate.row.prev",
    label: step === 1 ? "다음 행" : "이전 행",
    group: "navigate",
    shortcut: step === 1 ? KEY_MAP.rowDown : KEY_MAP.rowUp,
    icon: step === 1 ? "chevron-down" : "chevron-up",
    disabledReason: () => (currentRowSource()?.moveFocus ? undefined : NO_LIST_REASON),
    run: () => {
      // From the viewer the viewer keeps focus (it follows the new row); elsewhere focus lands on the row.
      const moved = currentRowSource()?.moveFocus?.({ step, domFocus: !focusInViewer() });
      if (moved === "end") announce(step === 1 ? "마지막 행입니다" : "첫 행입니다");
      if (moved === "unloaded") announce(UNLOADED_END);
    },
  };
}

/** Z, the advance setting and J / K (registered with the review keys). */
export function verdictFlowCommands(queryClient: QueryClient | null): Command[] {
  const advance = ADVANCE_MODES.map(
    (mode): Command => ({
      id: `review.advance.${mode}`,
      label: `판정 후 이동: ${ADVANCE_LABELS[mode]}`,
      group: "review",
      icon: "chevron-down",
      disabledReason: () =>
        useVerdictPrefs.getState().advance === mode ? "지금 쓰는 설정입니다" : undefined,
      run: () => {
        useVerdictPrefs.getState().setAdvance(mode);
        announce(`판정 후 이동: ${ADVANCE_LABELS[mode]}`);
      },
    }),
  );
  return [
    {
      id: "review.undo",
      label: "판정 되돌리기",
      group: "review",
      shortcut: KEY_MAP.undoVerdict,
      icon: "refresh",
      disabledReason: (ctx) => undoDisabledReason(ctx.runId),
      run: async () => {
        await undoLastVerdict(queryClient);
      },
    },
    ...advance,
    rowStepCommand(1),
    rowStepCommand(-1),
  ];
}

/** Apply a mark or tag to the context row; refreshes cached grid pages of the run on success. */
export async function applyToContextRow(
  queryClient: QueryClient | null,
  action: BatchAction,
  label: string,
  tag?: string,
): Promise<void> {
  const target = reviewTarget();
  if (!target) throw new Error(NO_ROW_REASON);
  // Prefer the grid's own row (exact pointer/case-db fields); otherwise derive it from the target.
  const row = useAppStore.getState().viewerRow ?? targetAsGridRow(target);
  const result = await applyReviewAction(target.runId, [row], action, tag ? { tag } : {});
  const text = `${label}: 1건 처리했습니다${storeNotice(result)}`;
  announce(text);
  useAppStore.getState().showNotice(text);
  await queryClient?.invalidateQueries({
    predicate: (query) => query.queryKey.includes(target.runId),
  });
}

/** Command id of digit `level`'s tag key (review.priority.1–5 kept for 1–5). */
export function tagKeyCommandId(level: number): string {
  return level <= PRIORITY_LEVELS.length ? `review.priority.${level}` : `review.tagKey.${level}`;
}

/**
 * Palette label of a digit tag key: the bound tag's name once the case's tags are loaded, else the
 * default (1–5: 우선순위 n), so "우선순위" and every tag name stay searchable in the palette.
 */
export function tagKeyLabel(level: number, tags?: readonly CaseTag[] | null): string {
  const bound = tags?.find((tag) => tag.shortcut === level);
  if (bound) return `태그 단축키 ${level} (${bound.name})`;
  if (tags && tags.length > 0) return `태그 단축키 ${level} (지정 안 됨)`;
  return level <= PRIORITY_LEVELS.length
    ? `태그 단축키 ${level} (기본: ${priorityTag(level)})`
    : `태그 단축키 ${level}`;
}

function loadedTags(): CaseTag[] | null {
  const state = useCaseTagStore.getState();
  return state.status === "ready" && state.exists ? state.tags : null;
}

/** Relabel the digit commands from the loaded tags (on every tag store change, below). */
export function relabelTagKeys(): void {
  const tags = loadedTags();
  for (const level of TAG_KEY_DIGITS) relabelCommand(tagKeyCommandId(level), tagKeyLabel(level, tags));
}

if (typeof window !== "undefined") {
  useCaseTagStore.subscribe((state, prev) => {
    if (state.tags !== prev.tags || state.status !== prev.status || state.exists !== prev.exists)
      relabelTagKeys();
  });
}

/** Undo of a pressed verdict toggle (viewer header): status back to 미판정 / out of the report. */
export const CLEAR_VERDICT_COMMAND = "review.clear";
export const UNREPORT_COMMAND = "review.unreport";

export function reviewCommands(queryClient: QueryClient | null): Command[] {
  const marks = MARKS.map(
    ({ action, label, shortcut }): Command => ({
      id: `review.mark.${action}`,
      label,
      group: "review",
      shortcut,
      icon: action === "bookmark" ? "bookmark" : "flag",
      disabledReason: (ctx) => verdictDisabledReason(action, ctx),
      run: async (ctx) => {
        await runVerdict(queryClient, action, { ctx });
      },
    }),
  );
  const unmarks: Command[] = [
    {
      id: CLEAR_VERDICT_COMMAND,
      label: "판정 해제 (미판정으로)",
      group: "review",
      icon: "close",
      disabledReason: (ctx) => verdictDisabledReason("relevant", ctx),
      run: async (ctx) => {
        await runVerdict(queryClient, "clear-review", { advance: false, ctx });
      },
    },
    {
      id: UNREPORT_COMMAND,
      label: "보고서 포함 해제",
      group: "review",
      icon: "close",
      disabledReason: (ctx) => verdictDisabledReason("include-in-report", ctx),
      run: async (ctx) => {
        await runVerdict(queryClient, "remove-from-report", { advance: false, ctx });
      },
    },
  ];
  // Digit keys (AXIOM E3): the case tag bound to the digit in 태그 관리 (1–5 default: 우선순위 n).
  // Ids review.priority.1–5 are kept; 6–9 are review.tagKey.n.
  const tagKey = (level: number, id: string): Command => ({
    id,
    label: tagKeyLabel(level, loadedTags()),
    group: "review",
    shortcut: String(level),
    icon: "tag",
    disabledReason: (ctx) => reasonFor("relevant", ctx.runId) ?? tagKeyReason(ctx.runId, level),
    run: async () => {
      const target = reviewTarget();
      if (!target) throw new Error(NO_ROW_REASON);
      const resolved = await resolveTagKey(target.runId, level);
      if (resolved.tag) await toggleCaseTagOnContextRow(queryClient, resolved.tag);
      else await applyToContextRow(queryClient, "tag", `태그 '${resolved.name}'`, resolved.name);
    },
  });
  const priorities = PRIORITY_LEVELS.map((level) => tagKey(level, tagKeyCommandId(level)));
  const extraKeys = TAG_KEY_DIGITS.filter((level) => level > PRIORITY_LEVELS.length).map((level) =>
    tagKey(level, tagKeyCommandId(level)),
  );
  return [...marks, ...unmarks, ...verdictFlowCommands(queryClient), ...priorities, ...extraKeys];
}
