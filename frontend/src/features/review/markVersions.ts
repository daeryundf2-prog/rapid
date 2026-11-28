/**
 * What the console last read of each review mark (design review F14). Every review-map load and
 * every write answer records the mark's `updated_at` per case-DB target, and which run-output
 * locator points at which target. A write sends the version back as `expected_updated_at`; the
 * server answers 409 when another examiner changed the mark since, instead of overwriting it.
 *
 * Versions only move forward (newest `updated_at` wins), so a slow review-map reload never brings
 * back a version older than the console's own last write.
 */

import type { ReviewMapMark } from "../../api/caseDb";

/** Review-map key of a run-output locator: `collection|kind|locator` (the kind only for artifacts / analysis). */
export function reviewKey(collection: string, kind: string, locator: string): string {
  return `${collection}|${collection === "artifacts" || collection === "analysis" ? kind : ""}|${locator}`;
}

/** One known mark: when it last changed, and the token the server compares ("" for a cleared mark). */
interface KnownVersion {
  at: string;
  token: string;
}

interface RunMarks {
  /** By `target_type:target_id`. */
  versions: Map<string, KnownVersion>;
  /** Locator key → `target_type:target_id`. */
  links: Map<string, string>;
  /** The last review map listed every mark (not truncated): a locator without one has no mark. */
  complete: boolean;
}

const runs = new Map<string, RunMarks>();

function runMarks(runId: string): RunMarks {
  let marks = runs.get(runId);
  if (!marks) {
    marks = { versions: new Map(), links: new Map(), complete: false };
    runs.set(runId, marks);
  }
  return marks;
}

function noteVersion(marks: RunMarks, target: string, at: string, active: boolean): void {
  const known = marks.versions.get(target);
  // ISO UTC instants of one server clock: string order is time order.
  if (known && known.at > at) return;
  marks.versions.set(target, { at, token: active ? at : "" });
}

/** A review-map load: every active mark it lists (a cleared mark is not listed). */
export function rememberReviewMarks(
  runId: string,
  marks: readonly ReviewMapMark[],
  truncated: boolean,
): void {
  const state = runMarks(runId);
  for (const mark of marks) {
    const target = `${mark.target_type}:${mark.target_id}`;
    noteVersion(state, target, mark.updated_at, true);
    if (mark.collection && mark.locator)
      state.links.set(reviewKey(mark.collection, mark.kind, mark.locator), target);
  }
  state.complete = !truncated;
}

/** A stored mark as a write answer returns it. */
export interface WrittenMark {
  target_type?: unknown;
  target_id?: unknown;
  updated_at?: unknown;
  /** false when the write cleared the mark (status back to unreviewed with nothing else). */
  active: boolean;
  /** The run-output locator the write addressed, when it addressed one. */
  locatorKey?: string | null;
}

/** A successful write: the new versions (and locator links) of the marks it stored. */
export function noteWrittenMarks(runId: string, marks: readonly WrittenMark[]): void {
  const state = runMarks(runId);
  for (const mark of marks) {
    if (typeof mark.target_type !== "string" || typeof mark.target_id !== "string") continue;
    if (typeof mark.updated_at !== "string") continue;
    const target = `${mark.target_type}:${mark.target_id}`;
    noteVersion(state, target, mark.updated_at, mark.active);
    if (mark.locatorKey) state.links.set(mark.locatorKey, target);
  }
}

/** Where a write goes: a case-DB target (`type:id`), or a run-output locator key. */
export type MarkAddress = { target: string; boardVersion?: string } | { locator: string };

/**
 * `expected_updated_at` of one write target: the version last read; "" when the complete review
 * map had no mark there; undefined (no check, the old behaviour) when nothing is known.
 * `boardVersion`: the board row's own `updated_at` (the board loads the marks itself).
 */
export function expectedVersion(runId: string, address: MarkAddress): string | undefined {
  const state = runs.get(runId);
  if ("target" in address) {
    const known = state?.versions.get(address.target);
    if (known && (!address.boardVersion || known.at >= address.boardVersion)) return known.token;
    return address.boardVersion;
  }
  if (!state) return undefined;
  const target = state.links.get(address.locator);
  const known = target ? state.versions.get(target) : undefined;
  if (known) return known.token;
  return state.complete ? "" : undefined;
}

/** Forget every run (tests; a run re-import). */
export function resetMarkVersions(): void {
  runs.clear();
}
