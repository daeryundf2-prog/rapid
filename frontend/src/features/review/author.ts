/**
 * Review author (AXIOM E3): the name written with tags, notes and baselines. Kept per browser
 * (localStorage through readStored/writeStored, which never throw); "web-ui" when unset, the
 * same default the console used before.
 */

import { readStored, writeStored } from "../../state/storage";

export const REVIEWER_STORAGE_KEY = "rapidtriage.reviewer";
export const DEFAULT_REVIEWER = "web-ui";
export const REVIEWER_MAX = 60;

export function currentReviewer(): string {
  const stored = (readStored(REVIEWER_STORAGE_KEY) ?? "").trim();
  return stored || DEFAULT_REVIEWER;
}

/** Saves the author name (empty → back to the default). */
export function setReviewer(name: string): void {
  const clean = name.replace(/\s+/g, " ").trim().slice(0, REVIEWER_MAX);
  writeStored(REVIEWER_STORAGE_KEY, clean || null);
}

/** Shown for a mark whose stored reviewer names nobody (F13). */
export const UNNAMED_REVIEWER_LABEL = "이름 없음";

/** Stored reviewer values that name no person: unset, the console's old default, the server's actor fallback. */
const UNNAMED_REVIEWERS = new Set(["", DEFAULT_REVIEWER, "local-user"]);

/** The reviewer as the board shows it: the stored name, or "이름 없음" for an empty / legacy default value. */
export function reviewerLabel(name: string | null | undefined): string {
  const clean = (name ?? "").trim();
  return UNNAMED_REVIEWERS.has(clean) ? UNNAMED_REVIEWER_LABEL : clean;
}

/**
 * "되돌림 (원래 판정: lee v3)": a write made by Z (re-review P2). Its actor is whoever pressed Z; this
 * names the verdict it undid — that verdict's reviewer and history version. The 메모·이력 list and
 * the review board's 판정자 tooltip both say it.
 */
export function undoText(undoneReviewer: string | null | undefined, undoneVersion: number): string {
  return `되돌림 (원래 판정: ${reviewerLabel(undoneReviewer)} v${undoneVersion})`;
}
