/**
 * Digit keys 1–9 (AXIOM E3): each toggles the case tag bound to that digit in 태그 관리 on the
 * row in context (viewer target / focused grid row or tile — the same row R/X/I/B act on). The
 * tag goes by its case_tag id (a rename never re-creates it); pressing the key again on a row
 * that carries the tag takes it off. The system tags 우선순위 1–5 hold keys 1–5 by default, so
 * the keys keep their meaning until the examiner rebinds them. Before the run has a case DB
 * there are no tags yet: 1–5 then still add 우선순위 n by name (the mark creates the DB and tag).
 */

import type { QueryClient } from "@tanstack/react-query";
import { announce } from "../../a11y";
import { type CaseTag, postTagBatch } from "../../api/reviewTools";
import { useAppStore } from "../../state/store";
import { notifyReviewApplied, reviewTargetOf } from "../grid/reviewActions";
import { targetAsGridRow } from "../viewer/citation";
import { currentReviewer } from "./author";
import { loadCaseTags, tagHandle, useCaseTagStore } from "./tagStore";

/** Built-in name of digit n's fallback tag (same as commands/review.ts priorityTag). */
const priorityTag = (level: number) => `우선순위 ${level}`;

export const TAG_KEY_DIGITS = [1, 2, 3, 4, 5, 6, 7, 8, 9] as const;
/** Digits that also have a built-in fallback tag (우선순위 n). */
const FALLBACK_LEVELS = 5;
export const NO_LOCATOR_REASON = "출처 위치를 알 수 없는 행에는 태그를 붙일 수 없습니다";

export function unboundKeyReason(digit: number): string {
  return `단축키 ${digit}에 지정된 태그가 없습니다. 태그 관리에서 지정하세요`;
}

/** Disabled reason of a digit key from the loaded tags (undefined while unknown). */
export function tagKeyReason(runId: string | null, digit: number): string | undefined {
  if (!runId) return undefined;
  const state = useCaseTagStore.getState();
  if (state.runId !== runId || state.status !== "ready") return undefined;
  if (!state.exists) return digit <= FALLBACK_LEVELS ? undefined : unboundKeyReason(digit);
  return state.tags.some((tag) => tag.shortcut === digit) ? undefined : unboundKeyReason(digit);
}

/** What a digit applies in this run (loads the tags first): the bound tag, or the 우선순위 name. */
export async function resolveTagKey(runId: string, digit: number): Promise<{ tag?: CaseTag; name: string }> {
  let exists = false;
  let bound: CaseTag | undefined;
  try {
    const tags = await loadCaseTags(runId);
    exists = useCaseTagStore.getState().exists;
    bound = tags.find((tag) => tag.shortcut === digit);
  } catch {
    exists = false;
  }
  if (bound) return { tag: bound, name: bound.name };
  if (!exists && digit <= FALLBACK_LEVELS) return { name: priorityTag(digit) };
  throw new Error(unboundKeyReason(digit));
}

/** Toggle a case tag on the context row (by id); says and shows the result once. */
export async function toggleCaseTagOnContextRow(
  queryClient: QueryClient | null,
  tag: CaseTag,
): Promise<void> {
  const state = useAppStore.getState();
  const target = state.viewerTarget;
  if (!target) throw new Error("표시할 행이 없습니다. 그리드에서 행을 선택하세요");
  const row = state.viewerRow ?? targetAsGridRow(target);
  const reviewTarget = reviewTargetOf(row);
  if (!reviewTarget) throw new Error(NO_LOCATOR_REASON);
  const has = row.tags.some((name) => name.toLocaleLowerCase() === tag.name.toLocaleLowerCase());
  const handle = await tagHandle(target.runId);
  await postTagBatch(handle, target.runId, [reviewTarget], {
    ...(has ? { remove_tag_ids: [tag.id] } : { tag_ids: [tag.id] }),
    reviewer: currentReviewer(),
  });
  notifyReviewApplied(target.runId);
  const text = has ? `태그 '${tag.name}' 해제: 1건 처리했습니다` : `태그 '${tag.name}': 1건 처리했습니다`;
  announce(text);
  useAppStore.getState().showNotice(text);
  await queryClient?.invalidateQueries({ predicate: (query) => query.queryKey.includes(target.runId) });
}
