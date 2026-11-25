/**
 * Full artifact record for the viewer.
 *
 * The grid pages artifacts with `view=list` (api/app/list_view.py): a row's `details` keeps
 * every flat field the grid reads but leaves out the nested parser profiles / manifests and
 * names them in `details_omitted` (GridRow `fields.detailsOmitted`). The viewer shows the
 * whole record, so for such a row it loads the record once (`fetchArtifactRecord`) and swaps
 * the full `details` in; until then (or if that request fails) it shows the list row.
 */

import { useEffect, useMemo, useState } from "react";
import { fetchArtifactRecord } from "../../api/collections";
import type { GridRow } from "../../contracts/collection";

type Details = Record<string, unknown>;

const MAX_CACHED = 64;
const cache = new Map<string, Details>();
const SEP = "\u0000";

function isRecord(value: unknown): value is Details {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
  cache.clear();
}

function remember(key: string, details: Details): void {
  cache.delete(key);
  cache.set(key, details);
  while (cache.size > MAX_CACHED) {
    const oldest = cache.keys().next().value;
    if (oldest === undefined) break;
    cache.delete(oldest);
  }
}

/** The row with its full record once loaded (the list row meanwhile, and for every other row). */
export function useFullRecordRow(row: GridRow | null, runId: string | null): GridRow | null {
  const key = fullRecordKey(row, runId);
  const [loaded, setLoaded] = useState<{ key: string; details: Details } | null>(null);
  useEffect(() => {
    if (!key) return;
    const cached = cache.get(key);
    if (cached) {
      setLoaded({ key, details: cached });
      return;
    }
    const [run, kind, index] = key.split(SEP) as [string, string, string];
    const controller = new AbortController();
    fetchArtifactRecord(run, kind, Number(index), controller.signal)
      .then((full) => {
        if (!full || !isRecord(full.details)) return;
        remember(key, full.details);
        setLoaded({ key, details: full.details });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        // The list row stays: its details still hold every flat field.
        console.warn(error instanceof Error ? error.message : error);
      });
    return () => controller.abort();
  }, [key]);
  return useMemo(
    () => (row && loaded && loaded.key === key ? withFullDetails(row, loaded.details) : row),
    [row, loaded, key],
  );
}
