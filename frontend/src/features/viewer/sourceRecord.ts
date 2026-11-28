/**
 * The decoded artifact record a timeline event points at (design-viewer-keys F18).
 *
 * Timeline rows are list-view events: `details.source_record` names the artifact row they came
 * from ({output: "artifacts_browser", row_index: 2}) but the event itself carries no URL, title
 * or visit count. The viewer loads that artifact record once (`fetchArtifactRecord`, the same
 * request the full-record loader uses) and shows it first — the decoded record, then hex.
 */

import { useEffect, useMemo, useSyncExternalStore } from "react";
import { fetchArtifactRecord, type RawRow } from "../../api/collections";
import type { GridRow } from "../../contracts/collection";
import type { Route } from "../../router";
import { artifactsCollection } from "../grid/columns/artifacts";
import { isRecord } from "../grid/columns/common";
import { artifactRowRoute } from "./pivots";

type Entry =
  | { status: "loading" }
  | { status: "loaded"; raw: RawRow | null }
  | { status: "failed"; error: string };

export interface SourceRecordRef {
  kind: string;
  index: number;
  /** "artifacts_browser" as the event names it. */
  output: string;
  route: Route;
}

const entries = new Map<string, Entry>();
const listeners = new Set<() => void>();
const MAX_CACHED = 64;

/** The artifact row a timeline event points at, or null (other rows, no `source_record`). */
export function sourceRecordRef(row: GridRow | null, runId: string | null): SourceRecordRef | null {
  if (!row || !runId || row.ref.collection !== "timeline") return null;
  const source = row.fields.sourceRecord;
  if (!isRecord(source)) return null;
  const route = artifactRowRoute(runId, source.output, source.row_index);
  const locator = route?.row?.locator ?? "";
  const index = Number(/\/(\d+)$/.exec(locator)?.[1]);
  if (!route?.kind || !Number.isInteger(index)) return null;
  return { kind: route.kind, index, output: String(source.output), route };
}

function keyOf(runId: string, ref: SourceRecordRef): string {
  return `${runId}\u0000${ref.kind}\u0000${ref.index}`;
}

function put(key: string, entry: Entry): void {
  entries.delete(key);
  entries.set(key, entry);
  for (const [oldest, value] of entries) {
    if (entries.size <= MAX_CACHED) break;
    if (value.status !== "loading") entries.delete(oldest);
  }
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function load(key: string, runId: string, ref: SourceRecordRef): void {
  const current = entries.get(key);
  if (current && current.status !== "failed") return;
  put(key, { status: "loading" });
  fetchArtifactRecord(runId, ref.kind, ref.index).then(
    (raw) => {
      if (entries.get(key)?.status === "loading") put(key, { status: "loaded", raw });
    },
    (error: unknown) => {
      if (entries.get(key)?.status === "loading")
        put(key, { status: "failed", error: error instanceof Error ? error.message : String(error) });
    },
  );
}

export function resetSourceRecords(): void {
  entries.clear();
  for (const listener of listeners) listener();
}

export interface SourceRecordState {
  ref: SourceRecordRef;
  status: "loading" | "loaded" | "missing" | "failed";
  /** The decoded artifact record as a grid row (artifacts collection mapping). */
  row: GridRow | null;
  error?: string;
}

/** The event's source artifact record (loading → loaded), or null for rows without one. */
export function useSourceRecord(row: GridRow | null, runId: string | null): SourceRecordState | null {
  const ref = useMemo(() => sourceRecordRef(row, runId), [row, runId]);
  const key = ref && runId ? keyOf(runId, ref) : null;
  const entry = useSyncExternalStore(subscribe, () => (key ? entries.get(key) : undefined));
  useEffect(() => {
    if (key && ref && runId) load(key, runId, ref);
  }, [key, ref, runId]);
  return useMemo(() => {
    if (!ref) return null;
    if (!entry || entry.status === "loading") return { ref, status: "loading", row: null };
    if (entry.status === "failed") return { ref, status: "failed", row: null, error: entry.error };
    if (!entry.raw) return { ref, status: "missing", row: null };
    const mapped = artifactsCollection.mapRow(entry.raw, ref.index, {
      ref: { id: "artifacts", kind: ref.kind },
    });
    return { ref, status: "loaded", row: mapped };
  }, [ref, entry]);
}

/** The loaded source record of a timeline row, read synchronously (pivot keys, citation). */
export function cachedSourceRow(row: GridRow | null, runId: string | null): GridRow | null {
  const ref = sourceRecordRef(row, runId);
  if (!ref || !runId) return null;
  const entry = entries.get(keyOf(runId, ref));
  if (entry?.status !== "loaded" || !entry.raw) return null;
  return artifactsCollection.mapRow(entry.raw, ref.index, { ref: { id: "artifacts", kind: ref.kind } });
}
