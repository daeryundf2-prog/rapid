/**
 * Cross-case result rows (plan analysis-workbench-p1 §3.2 `cross-case`): each shared
 * indicator lists the runs ("cases") it occurs in and up to 20 occurrences
 * `{case_id, case_scope, citation_id, path, run_id, target}`. `case_id` is the run id (the API
 * maps each case DB back to its run); `run_id` repeats it and `target` is the occurrence's
 * run-output locator `{collection, kind, locator}|null` (review-map shape). Every helper
 * reads all of these defensively so older rows still link.
 */

import { runDisplayName } from "../../app/collections";
import type { RowRef } from "../../contracts/rowRef";
import type { Route } from "../../router";
import { serializeRoute } from "../../router";
import { useAppStore } from "../../state/store";

export interface CrossCaseOccurrence {
  runId: string;
  caseScope: string | null;
  citationId: string | null;
  path: string | null;
  /** Run-output locator of the occurrence's row, when the server reports one. */
  row: RowRef | null;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function crossCaseOccurrences(details: Record<string, unknown>): CrossCaseOccurrence[] {
  const raw = Array.isArray(details.occurrences) ? details.occurrences : [];
  const out: CrossCaseOccurrence[] = [];
  for (const item of raw) {
    const o = record(item);
    if (!o) continue;
    const runId = text(o.run_id) ?? text(o.case_id);
    if (!runId) continue;
    // `target: {collection, kind, locator}|null` (review-map shape; kind "" outside artifacts),
    // or the same keys flat on the occurrence.
    const target = record(o.target) ?? o;
    const collection = text(target.collection);
    const locator = text(target.locator);
    const kind = text(target.kind);
    out.push({
      runId,
      caseScope: text(o.case_scope),
      citationId: text(o.citation_id),
      path: text(o.path),
      row:
        collection && locator
          ? { collection: collection as RowRef["collection"], locator, ...(kind ? { kind } : {}) }
          : null,
    });
  }
  return out;
}

/** Run ids of a cross-case row: `cases[]` plus every occurrence's run (first-seen order). */
export function crossCaseRunIds(details: Record<string, unknown>): string[] {
  const ids: string[] = [];
  const add = (id: string | null) => {
    if (id && !ids.includes(id)) ids.push(id);
  };
  if (Array.isArray(details.cases)) for (const id of details.cases) add(text(id));
  for (const occurrence of crossCaseOccurrences(details)) add(occurrence.runId);
  return ids;
}

/**
 * Where an occurrence opens in its run: its own row when the server gave a locator, else
 * the files list filtered to its path, else a search for the indicator (hash rows).
 */
export function occurrenceRoute(occurrence: CrossCaseOccurrence, indicator: string | null): Route {
  if (occurrence.row) {
    return {
      runId: occurrence.runId,
      collection: occurrence.row.collection as Route["collection"],
      ...(occurrence.row.kind ? { kind: occurrence.row.kind } : {}),
      row: occurrence.row,
    };
  }
  if (occurrence.path) return { runId: occurrence.runId, collection: "files", path: occurrence.path };
  if (indicator) return { runId: occurrence.runId, collection: "search", q: indicator };
  return { runId: occurrence.runId, collection: "files" };
}

/** Route opening one case of a row: its first occurrence there, else the run's files list. */
export function caseRoute(details: Record<string, unknown>, runId: string): Route {
  const indicator = text(details.indicator);
  const hit = crossCaseOccurrences(details).find((o) => o.runId === runId);
  if (hit) return occurrenceRoute(hit, indicator);
  return indicator && text(details.kind) !== "path"
    ? { runId, collection: "search", q: indicator }
    : { runId, collection: "files" };
}

export function caseHref(details: Record<string, unknown>, runId: string): string {
  return serializeRoute(caseRoute(details, runId));
}

/** "BSH.E01 (1a2b3c4d)" — the run's display name when the console knows the run. */
export function caseLabel(runId: string): string {
  const run = useAppStore.getState().runs.find((r) => r.run_id === runId);
  return run ? `${runDisplayName(run)} (${runId.slice(0, 8)})` : runId.slice(0, 12);
}

/** Other cases of a row, relative to the open run. */
export function otherCaseIds(details: Record<string, unknown>, currentRun: string | null): string[] {
  return crossCaseRunIds(details).filter((id) => id !== currentRun);
}
