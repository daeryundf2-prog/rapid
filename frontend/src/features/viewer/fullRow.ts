/**
 * Full artifact details for the viewer (R7 S1). The grid lists artifacts with `compact=1`: large
 * nested `details` values (parser profiles, citation manifests, raw record dumps) are left out of
 * each grid row and named in `fields.detailsOmitted`. When the viewer shows such a row it fetches
 * the one full row (`kind=<k>&offset=<record_index>&limit=1`, not compact) and reads its
 * `details`; everything else (review status, tags, flags) still comes from the live grid row.
 */

import { useEffect, useMemo, useState } from "react";
import { api } from "../../api/client";
import type { GridRow } from "../../contracts/collection";

type Details = Record<string, unknown>;

const CACHE_SIZE = 50;
const cache = new Map<string, Details>();
const inFlight = new Map<string, Promise<Details | null>>();

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The record index of an artifacts row ref (`/artifacts/<n>`), or null. */
export function artifactRecordIndex(row: GridRow): number | null {
  const match = /^\/artifacts\/(\d+)$/.exec(row.ref.locator);
  return match ? Number(match[1]) : null;
}

/** True when the grid row's details were compacted by the server. */
export function rowNeedsFullDetails(row: GridRow | null): row is GridRow {
  if (row?.ref.collection !== "artifacts" || !row.ref.kind) return false;
  const omitted = row.fields.detailsOmitted;
  return Array.isArray(omitted) && omitted.length > 0 && artifactRecordIndex(row) !== null;
}

function cacheKey(runId: string, row: GridRow): string {
  return `${runId}|${row.ref.kind ?? ""}|${row.ref.locator}`;
}

function remember(key: string, details: Details): void {
  cache.delete(key);
  cache.set(key, details);
  while (cache.size > CACHE_SIZE) {
    const oldest = cache.keys().next().value;
    if (oldest === undefined) break;
    cache.delete(oldest);
  }
}

/** Full `details` of one artifact row (deduplicated, cached); null when the server has no such row. */
export function loadFullDetails(runId: string, row: GridRow): Promise<Details | null> {
  const key = cacheKey(runId, row);
  const hit = cache.get(key);
  if (hit) return Promise.resolve(hit);
  const pending = inFlight.get(key);
  if (pending) return pending;
  const kind = row.ref.kind as string;
  const index = artifactRecordIndex(row) as number;
  const params = new URLSearchParams({ kind, offset: String(index), limit: "1" });
  const request = api<{ artifacts?: Record<string, { artifacts?: unknown[] }> }>(
    `/api/runs/${encodeURIComponent(runId)}/artifacts?${params}`,
  )
    .then((payload) => {
      const first = payload.artifacts?.[kind]?.artifacts?.[0];
      // Only the exact record: offset == record_index for an unfiltered, unsorted listing.
      if (!isRecord(first) || first.record_index !== index || !isRecord(first.details)) return null;
      remember(key, first.details);
      return first.details;
    })
    .finally(() => inFlight.delete(key));
  inFlight.set(key, request);
  return request;
}

/** Drop cached full rows (tests; a run re-import). */
export function resetFullDetailsCache(): void {
  cache.clear();
  inFlight.clear();
}

/**
 * The viewer's row with full `details` once loaded (the compact grid row until then, or when the
 * fetch fails — the record section then shows what the grid had).
 */
export function useFullArtifactRow(runId: string | null | undefined, row: GridRow | null): GridRow | null {
  const key = runId && rowNeedsFullDetails(row) ? cacheKey(runId, row) : null;
  const [loaded, setLoaded] = useState<{ key: string; details: Details } | null>(null);
  // biome-ignore lint/correctness/useExhaustiveDependencies: keyed on the row's identity (run · kind · record), not its object
  useEffect(() => {
    if (!key || !runId || !row || cache.has(key)) return;
    let alive = true;
    loadFullDetails(runId, row)
      .then((details) => {
        if (alive && details) setLoaded({ key, details });
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [key]);
  const details = key ? (cache.get(key) ?? (loaded?.key === key ? loaded.details : undefined)) : undefined;
  return useMemo(() => {
    if (!row || !details) return row;
    const { detailsOmitted: _omitted, ...fields } = row.fields;
    return { ...row, fields: { ...fields, details } };
  }, [row, details]);
}
