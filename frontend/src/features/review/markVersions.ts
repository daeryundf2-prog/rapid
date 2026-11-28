/**
 * Review-mark versions (design review F14, review P1-1 / P3-1 / P3-2 / P3-3).
 *
 * Every mark has a version token: its newest history version on the server, 0 when there is no
 * mark (never made, or cleared). A write sends, per target, the version of the mark the examiner
 * SAW (`expected_version`); the server answers 409 when another examiner changed it since,
 * instead of overwriting their decision.
 *
 * What the examiner saw is pinned when the edit begins: a note form or the 메모·이력 panel pins
 * when it opens, a row action pins the version drawn on that row (`fields.markVersion`, from the
 * review map overlay or the board). A background review-map reload moves the console's newest
 * known version (`currentVersion`, the fallback when a row carries none) but never a pin.
 *
 * The console's own writes do not conflict with itself: every write answer reports
 * `previous_version → version` per mark, and so does an acknowledged conflict (the examiner saw
 * the current mark in the prompt). `resolvePin` replays those steps, in order, over a pin.
 */

import type { ReviewMapMark } from "../../api/caseDb";

/** Review-map key of a run-output locator: `collection|kind|locator` (the kind only for artifacts / analysis). */
export function reviewKey(collection: string, kind: string, locator: string): string {
  return `${collection}|${collection === "artifacts" || collection === "analysis" ? kind : ""}|${locator}`;
}

interface RunMarks {
  /** Newest known version by `target_type:target_id`. */
  versions: Map<string, number>;
  /** Locator key → `target_type:target_id`. */
  links: Map<string, string>;
  /** The console's own steps per target, oldest first: `[from, to]`. */
  steps: Map<string, Array<readonly [number, number]>>;
  /** Write sequence number of the console's last write per target. */
  written: Map<string, number>;
  /** The last review map listed every mark (not truncated): a locator without one has no mark. */
  complete: boolean;
}

const runs = new Map<string, RunMarks>();
let writeSeq = 0;

function runMarks(runId: string): RunMarks {
  let marks = runs.get(runId);
  if (!marks) {
    marks = { versions: new Map(), links: new Map(), steps: new Map(), written: new Map(), complete: false };
    runs.set(runId, marks);
  }
  return marks;
}

/** The sequence number of the console's writes so far; a review-map load passes it to `rememberReviewMarks`. */
export function markWriteSeq(): number {
  return writeSeq;
}

/**
 * A review-map load: every active mark it lists (a cleared mark is not listed). `since`: the
 * write sequence when the load started; a target the console wrote after that keeps its own
 * newer version. A complete map also says every other known target has no mark now (P3-3).
 */
export function rememberReviewMarks(
  runId: string,
  marks: readonly ReviewMapMark[],
  truncated: boolean,
  since = Number.POSITIVE_INFINITY,
): void {
  const state = runMarks(runId);
  const newer = (target: string) => (state.written.get(target) ?? -1) >= since;
  const listed = new Set<string>();
  for (const mark of marks) {
    const target = `${mark.target_type}:${mark.target_id}`;
    listed.add(target);
    if (mark.collection && mark.locator)
      state.links.set(reviewKey(mark.collection, mark.kind, mark.locator), target);
    if (typeof mark.version === "number" && !newer(target)) state.versions.set(target, mark.version);
  }
  state.complete = !truncated;
  if (truncated) return;
  for (const target of state.versions.keys()) {
    if (!listed.has(target) && !newer(target)) state.versions.set(target, 0);
  }
}

/** One mark a write stored: the version it replaced and the one it made (0 = cleared). */
export interface WrittenMark {
  target_type: string;
  target_id: string;
  previous_version: number;
  version: number;
  /** The run-output locator the write addressed, when it addressed one. */
  locatorKey?: string | null;
}

function addStep(state: RunMarks, target: string, from: number, to: number): void {
  const steps = state.steps.get(target);
  if (steps) steps.push([from, to]);
  else state.steps.set(target, [[from, to]]);
}

/** A successful write of this console: the new versions, the steps, the locator links. */
export function noteWrittenMarks(runId: string, marks: readonly WrittenMark[]): void {
  const state = runMarks(runId);
  writeSeq += 1;
  for (const mark of marks) {
    const target = `${mark.target_type}:${mark.target_id}`;
    if (mark.locatorKey) state.links.set(mark.locatorKey, target);
    state.versions.set(target, mark.version);
    state.written.set(target, writeSeq);
    addStep(state, target, mark.previous_version, mark.version);
  }
}

/** Where a write goes: a case-DB target (`type:id`), or a run-output locator key. */
export type MarkAddress = { target: string } | { locator: string };

function targetOf(state: RunMarks | undefined, address: MarkAddress): string | undefined {
  return "target" in address ? address.target : state?.links.get(address.locator);
}

/**
 * The examiner saw `to` in place of `from` (the conflict prompt showed the current mark), so a pin
 * on `from` now means `to`.
 */
export function noteSeenVersion(runId: string, address: MarkAddress, from: number, to: number): void {
  const state = runMarks(runId);
  const target = targetOf(state, address);
  if (target) addStep(state, target, from, to);
}

/**
 * The newest version the console knows (fallback when a row carries none): 0 when the complete
 * review map had no mark there; undefined (no check, the old behaviour) when nothing is known.
 */
export function currentVersion(runId: string, address: MarkAddress): number | undefined {
  const state = runs.get(runId);
  if (!state) return undefined;
  const target = targetOf(state, address);
  const known = target ? state.versions.get(target) : undefined;
  if (known !== undefined) return known;
  return state.complete ? 0 : undefined;
}

/** A pin after the console's own steps since it was taken (its own writes, acknowledged conflicts). */
export function resolvePin(runId: string, address: MarkAddress, pin: number | undefined): number | undefined {
  if (pin === undefined) return undefined;
  const state = runs.get(runId);
  const target = targetOf(state, address);
  const steps = target ? state?.steps.get(target) : undefined;
  let version = pin;
  for (const [from, to] of steps ?? []) if (from === version) version = to;
  return version;
}

/** Forget every run (tests; a run re-import). */
export function resetMarkVersions(): void {
  runs.clear();
  writeSeq = 0;
}
