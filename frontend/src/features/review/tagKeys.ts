/**
 * Digit keys 1–9 (AXIOM E3): each applies the case tag bound to that digit in 태그 관리 to the
 * row in context (viewer target / focused grid row or tile), through the same
 * `applyToContextRow` as R/X/I/B. The system tags 우선순위 1–5 hold keys 1–5 by default, so the
 * keys keep their meaning until the examiner rebinds them. Before the run has a case DB there
 * are no tags yet: 1–5 then still mean 우선순위 n (the mark creates the DB and the tag).
 */

import { loadCaseTags, useCaseTagStore } from "./tagStore";

/** Built-in name of digit n's fallback tag (same as commands/review.ts priorityTag). */
const priorityTag = (level: number) => `우선순위 ${level}`;

export const TAG_KEY_DIGITS = [1, 2, 3, 4, 5, 6, 7, 8, 9] as const;
/** Digits that also have a built-in fallback tag (우선순위 n). */
const FALLBACK_LEVELS = 5;

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

/** The tag name a digit applies in this run (loads the tags first); throws the Korean reason. */
export async function tagNameForKey(runId: string, digit: number): Promise<string> {
  let exists = false;
  let bound: string | undefined;
  try {
    const tags = await loadCaseTags(runId);
    exists = useCaseTagStore.getState().exists;
    bound = tags.find((tag) => tag.shortcut === digit)?.name;
  } catch {
    exists = false;
  }
  if (bound) return bound;
  if (!exists && digit <= FALLBACK_LEVELS) return priorityTag(digit);
  throw new Error(unboundKeyReason(digit));
}
