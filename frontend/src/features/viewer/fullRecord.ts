/**
 * Full artifact record for the viewer.
 *
 * The grid pages artifacts with `view=list` (api/app/list_view.py): a row's `details` keeps
 * every flat field the grid reads but leaves out the nested parser profiles / manifests and
 * names them in `details_omitted` (GridRow `fields.detailsOmitted`). The viewer shows the
 * whole record, so for such a row it loads the record once (`fetchArtifactRecord`; one request
 * per record, shared by every viewer component) and swaps the full `details` in. Until then,
 * or when that request fails, `useFullRecordStatus` says what is missing: the record section
 * shows it (with 다시 시도 after a failure) and the record JSON cannot be copied, so a partial
 * record is never presented or copied as the whole one.
 */

import { useEffect, useMemo, useSyncExternalStore } from "react";
import { fetchArtifactRecord } from "../../api/collections";
import type { GridRow } from "../../contracts/collection";
import { isRecord } from "../grid/columns/common";

type Details = Record<string, unknown>;
type Entry =
  | { status: "loading" }
  | { status: "loaded"; details: Details }
  | { status: "failed"; error: string };

/** What the viewer's row still lacks while its full record is not loaded. */
export interface FullRecordStatus {
  /** `details` keys the list row leaves out (`key` or `key.member`). */
  omitted: string[];
  status: "loading" | "failed";
  error?: string;
  /** Request the record again (after a failure). */
  retry: () => void;
}

const MAX_CACHED = 64;
const entries = new Map<string, Entry>();
const listeners = new Set<() => void>();
const SEP = "\u0000";

export const FULL_RECORD_MISSING = "서버가 이 레코드를 돌려주지 않았습니다";
export const PARTIAL_COPY_REASON = "전체 레코드를 불러온 뒤 복사할 수 있습니다.";

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
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

/** Cache key `run · kind · record_index` of a list row that lacks part of its details, else null. */
export function fullRecordKey(row: GridRow | null, runId: string | null): string | null {
  if (!row || !runId || row.ref.collection !== "artifacts" || !row.ref.kind) return null;
  const omitted = row.fields.detailsOmitted;
  if (!Array.isArray(omitted) || omitted.length === 0) return null;
  const match = /^\/artifacts\/(\d+)$/.exec(row.ref.locator);
  return match ? [runId, row.ref.kind, match[1]].join(SEP) : null;
}

/** `row` with the record's full `details` (and no `detailsOmitted`). */
export function withFullDetails(row: GridRow, details: Details): GridRow {
  const { detailsOmitted: _omitted, ...fields } = row.fields;
  return { ...row, fields: { ...fields, details } };
}

export function resetFullRecordCache(): void {
  entries.clear();
  for (const listener of listeners) listener();
}

/** Request the record behind `key` unless it is loaded or on its way. */
function load(key: string): void {
  const current = entries.get(key);
  if (current && current.status !== "failed") return;
  put(key, { status: "loading" });
  const [run, kind, index] = key.split(SEP) as [string, string, string];
  fetchArtifactRecord(run, kind, Number(index)).then(
    (full) => {
      if (entries.get(key)?.status !== "loading") return; // reset meanwhile
      put(
        key,
        full && isRecord(full.details)
          ? { status: "loaded", details: full.details }
          : { status: "failed", error: FULL_RECORD_MISSING },
      );
    },
    (error: unknown) => {
      if (entries.get(key)?.status !== "loading") return;
      put(key, { status: "failed", error: error instanceof Error ? error.message : String(error) });
    },
  );
}

function useEntry(row: GridRow | null, runId: string | null): [string | null, Entry | undefined] {
  const key = fullRecordKey(row, runId);
  const entry = useSyncExternalStore(subscribe, () => (key ? entries.get(key) : undefined));
  useEffect(() => {
    if (key) load(key);
  }, [key]);
  return [key, entry];
}

/** The row with its full record once loaded (the list row meanwhile, and for every other row). */
export function useFullRecordRow(row: GridRow | null, runId: string | null): GridRow | null {
  const [, entry] = useEntry(row, runId);
  return useMemo(
    () => (row && entry?.status === "loaded" ? withFullDetails(row, entry.details) : row),
    [row, entry],
  );
}

/** What `row` still lacks (null when it is a whole record or its full record is loaded). */
export function useFullRecordStatus(row: GridRow | null, runId: string | null): FullRecordStatus | null {
  const [key, entry] = useEntry(row, runId);
  return useMemo(() => {
    if (!key || !row || entry?.status === "loaded") return null;
    const raw = row.fields.detailsOmitted;
    const omitted = Array.isArray(raw) ? raw.map(String) : [];
    const retry = () => load(key);
    return entry?.status === "failed"
      ? { omitted, status: "failed", error: entry.error, retry }
      : { omitted, status: "loading", retry };
  }, [key, row, entry]);
}
