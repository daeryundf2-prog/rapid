/**
 * Review author (AXIOM E3, r8 T-036): the name written with tags, notes, baselines and marks.
 * The name typed in a 작성자 field is kept per browser (localStorage through readStored /
 * writeStored, which never throw); when none was typed, the case's 담당자 (검사관, from the run's
 * processing snapshot) signs instead. With neither, no name is sent ("") and the server keeps its
 * own attribution (`RAPIDTRIAGE_REVIEWER`, else the row's previous reviewer) — the console never
 * writes a system id such as "web-ui" as the author (GAP-025, IS-043).
 */

import { readStored, writeStored } from "../../state/storage";
import { useAppStore } from "../../state/store";
import { useCaseLinks } from "../case/caseLink";

export const REVIEWER_STORAGE_KEY = "rapidtriage.reviewer";
/** No author known: an empty name (the server keeps its own attribution; never "web-ui"). */
export const DEFAULT_REVIEWER = "";
/** Placeholder of the 작성자 fields. */
export const REVIEWER_PLACEHOLDER = "담당자 이름";
export const REVIEWER_MAX = 60;

/** The case's 담당자 (검사관) for `runId` (default: the open run); "" when unknown. */
export function caseExaminer(runId?: string | null): string {
  const run = runId ?? useAppStore.getState().route.runId ?? null;
  if (!run) return "";
  return (useCaseLinks.getState().byRun[run]?.examiner ?? "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, REVIEWER_MAX);
}

/** The name typed in a 작성자 field ("" when none: the field shows the 담당자 as its placeholder). */
export function typedReviewer(): string {
  return (readStored(REVIEWER_STORAGE_KEY) ?? "").trim();
}

/** The typed author name, else the case's 담당자, else "" (see module comment). */
export function currentReviewer(runId?: string | null): string {
  return typedReviewer() || caseExaminer(runId) || DEFAULT_REVIEWER;
}

/** Placeholder of a 작성자 field: the case's 담당자 when known (who signs when it stays empty). */
export function reviewerPlaceholder(runId?: string | null): string {
  return caseExaminer(runId) || REVIEWER_PLACEHOLDER;
}

/** Saves the author name (empty → back to the case's 담당자). */
export function setReviewer(name: string): void {
  const clean = name.replace(/\s+/g, " ").trim().slice(0, REVIEWER_MAX);
  writeStored(REVIEWER_STORAGE_KEY, clean || null);
}
