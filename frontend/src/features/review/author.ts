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
