/**
 * Review keys (plan U5): R / X / I / B mark, 1–5 priority tags. One command
 * per key; each applies to the row in context — the viewer target when the
 * viewer has focus, otherwise the grid's focused row (the viewer target
 * follows grid focus). All marks go through the single shared implementation
 * `applyReviewAction` (features/grid/reviewActions.ts), the same code the grid
 * batch bar and the viewer toolbar use.
 */

import type { QueryClient } from "@tanstack/react-query";
import { announce } from "../a11y";
import { type Command, KEY_MAP } from "../contracts/command";
import type { MarkAction, ViewerTarget } from "../contracts/viewer";
import { applyReviewAction, type BatchAction, storeNotice } from "../features/grid/reviewActions";
import {
  resolveTagKey,
  TAG_KEY_DIGITS,
  tagKeyReason,
  toggleCaseTagOnContextRow,
} from "../features/review/tagKeys";
import { markDisabledReason, targetAsGridRow } from "../features/viewer/citation";
import { useAppStore } from "../state/store";
import { NO_RUN_REASON } from "./reasons";

export const NO_ROW_REASON = "표시할 행이 없습니다. 그리드에서 행을 선택하세요";
export const PRIORITY_LEVELS = [1, 2, 3, 4, 5] as const;

export const priorityTag = (level: number) => `우선순위 ${level}`;

const MARKS: ReadonlyArray<{ action: MarkAction; label: string; shortcut?: string }> = [
  { action: "relevant", label: "관련 있음 표시", shortcut: KEY_MAP.markRelevant },
  { action: "excluded", label: "제외 표시", shortcut: KEY_MAP.markExcluded },
  { action: "needs-review", label: "재검토 표시", shortcut: KEY_MAP.markNeedsReview },
  { action: "bookmark", label: "북마크", shortcut: KEY_MAP.bookmark },
  { action: "include-in-report", label: "보고서 포함 표시" },
];

/** The row the keys act on (see module comment). */
export function reviewTarget(): ViewerTarget | null {
  return useAppStore.getState().viewerTarget;
}

function reasonFor(action: MarkAction, runId: string | null): string | undefined {
  if (!runId) return NO_RUN_REASON;
  const target = reviewTarget();
  if (!target) return NO_ROW_REASON;
  return markDisabledReason(target, action);
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

export function reviewCommands(queryClient: QueryClient | null): Command[] {
  const marks = MARKS.map(
    ({ action, label, shortcut }): Command => ({
      id: `review.mark.${action}`,
      label,
      group: "review",
      shortcut,
      icon: action === "bookmark" ? "bookmark" : "flag",
      disabledReason: (ctx) => reasonFor(action, ctx.runId),
      run: () => applyToContextRow(queryClient, action, label),
    }),
  );
  // Digit keys (AXIOM E3): the case tag bound to the digit in 태그 관리 (1–5 default: 우선순위 n).
  // Ids review.priority.1–5 are kept; 6–9 are review.tagKey.n.
  const tagKey = (level: number, id: string): Command => ({
    id,
    label: `태그 단축키 ${level}`,
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
  const priorities = PRIORITY_LEVELS.map((level) => tagKey(level, `review.priority.${level}`));
  const extraKeys = TAG_KEY_DIGITS.filter((level) => level > PRIORITY_LEVELS.length).map((level) =>
    tagKey(level, `review.tagKey.${level}`),
  );
  return [...marks, ...priorities, ...extraKeys];
}
