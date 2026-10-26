import { ApiError, api } from "./client";
import type { RawPage, RawRow } from "./collections";

/**
 * Console global search over the run's v2 search index (R7 P2): `POST /search/query` with the
 * analyst's `keywords` answers v1-shaped hits (`matches`, finalize_search_hit on the server), so
 * the grid, the viewer and the review marks read both alike. Used when the index is `ready`
 * and the search options are the defaults v2 covers (exact keywords, no OCR / sources /
 * extensions / known-good hiding); everything else stays on v1 `GET /search`.
 *
 * v2 pages by cursor, the grid by offset: each page's `next_cursor` is remembered under
 * (run, keywords, next offset). A page whose cursor is not known yet waits for the request that
 * will return it, else walks forward from the nearest known cursor (up to 1,000 rows a request).
 */

export type SearchIndexStatus = "none" | "building" | "ready" | "stale" | "unknown";

const enc = encodeURIComponent;
/** Index status is re-read at most this often per run (a build finishing shows up within it). */
export const SEARCH_INDEX_STATUS_TTL_MS = 30_000;
const WALK_LIMIT = 1000;

const statusCache = new Map<string, { at: number; promise: Promise<SearchIndexStatus> }>();

function asStatus(value: unknown): SearchIndexStatus {
  return value === "none" || value === "building" || value === "ready" || value === "stale"
    ? value
    : "unknown";
}

/** `GET /api/runs/{run}/search/index` → `none | building | ready | stale` ("unknown" on errors). */
export function searchIndexStatus(runId: string, now: number = Date.now()): Promise<SearchIndexStatus> {
  const cached = statusCache.get(runId);
  if (cached && now - cached.at < SEARCH_INDEX_STATUS_TTL_MS) return cached.promise;
  // Shared by every page of every search: never tied to one request's AbortSignal.
  const promise = api<{ status?: unknown }>(`/api/runs/${enc(runId)}/search/index`)
    .then((payload) => asStatus(payload.status))
    .catch(() => "unknown" as const);
  statusCache.set(runId, { at: now, promise });
  return promise;
}

/** Drop the cached index status (one run, or all) and that run's remembered cursors. */
export function forgetSearchIndex(runId?: string): void {
  if (runId === undefined) {
    statusCache.clear();
    cursors.clear();
    pending.clear();
    return;
  }
  statusCache.delete(runId);
  for (const key of [...cursors.keys()]) if (key.startsWith(`${runId}\u0000`)) cursors.delete(key);
  for (const key of [...pending.keys()]) if (key.startsWith(`${runId}\u0000`)) pending.delete(key);
}

export interface IndexSearchSpec {
  keywords: string[];
  mode: "exact" | "fuzzy" | "regex";
  sources?: string[];
  hideKnownGood?: boolean;
  ocr?: boolean;
}

/** Options the v2 console query answers like v1 (anything else: v1 `GET /search`). */
export function indexCoversSearch(spec: IndexSearchSpec, extensions: readonly string[] | undefined): boolean {
  return (
    spec.mode === "exact" &&
    spec.keywords.length > 0 &&
    !spec.ocr &&
    !spec.hideKnownGood &&
    (spec.sources ?? []).length === 0 &&
    (extensions ?? []).length === 0
  );
}

/** next offset → cursor (null: the result ended there), per (run, keywords). */
const cursors = new Map<string, Map<number, string | null>>();
/** (run, keywords, offset) → the in-flight request that will name the cursor at that offset. */
const pending = new Map<string, Promise<string | null>>();

function searchKey(runId: string, keywords: readonly string[]): string {
  return `${runId}\u0000${JSON.stringify(keywords)}`;
}

function remember(key: string, offset: number, cursor: string | null): void {
  let known = cursors.get(key);
  if (!known) {
    known = new Map();
    cursors.set(key, known);
  }
  known.set(offset, cursor);
}

interface QueryPayload {
  matches?: unknown;
  page?: { next_cursor?: unknown };
  truncated?: unknown;
  elapsed_ms?: unknown;
}

function nextCursorOf(payload: QueryPayload): string | null {
  return typeof payload.page?.next_cursor === "string" && payload.page.next_cursor
    ? payload.page.next_cursor
    : null;
}

function postQuery(
  runId: string,
  keywords: readonly string[],
  cursor: string | null,
  limit: number,
  offset: number,
  signal?: AbortSignal,
): Promise<QueryPayload> {
  return api<QueryPayload>(`/api/runs/${enc(runId)}/search/query`, {
    method: "POST",
    signal,
    body: JSON.stringify({
      keywords,
      page: { limit, offset, ...(cursor ? { cursor } : {}) },
      // The grid needs one page fast: no total/facets pass (v1 knows its total only at the end too).
      aggregates: false,
      facets: false,
    }),
  });
}

/** The cursor that starts the page at `offset` (null: no rows there). */
async function cursorAt(
  runId: string,
  keywords: readonly string[],
  offset: number,
  signal?: AbortSignal,
): Promise<string | null> {
  const key = searchKey(runId, keywords);
  const known = cursors.get(key);
  if (known?.has(offset)) return known.get(offset) ?? null;
  const waiting = pending.get(`${key}\u0000${offset}`);
  if (waiting) {
    try {
      return await waiting;
    } catch {
      // The request that would have named it failed or was cancelled: walk instead.
    }
    const settled = cursors.get(key);
    if (settled?.has(offset)) return settled.get(offset) ?? null;
  }
  // Walk forward from the nearest known cursor before `offset` (0 = the first page).
  let at = 0;
  let cursor: string | null = null;
  for (const [knownOffset, knownCursor] of cursors.get(key) ?? []) {
    if (knownOffset < offset && knownOffset > at && knownCursor) {
      at = knownOffset;
      cursor = knownCursor;
    }
  }
  while (at < offset) {
    const payload = await postQuery(runId, keywords, cursor, Math.min(WALK_LIMIT, offset - at), at, signal);
    const returned = Array.isArray(payload.matches) ? payload.matches.length : 0;
    const next = nextCursorOf(payload);
    at += returned;
    remember(key, at, next);
    if (!next || returned === 0) return at === offset ? next : null;
    cursor = next;
  }
  return cursor;
}

/** One grid page of the console search from the v2 index (same paging semantics as v1). */
export async function fetchIndexSearchPage(
  runId: string,
  keywords: readonly string[],
  offset: number,
  limit: number,
  signal?: AbortSignal,
): Promise<RawPage> {
  try {
    return await indexPage(runId, keywords, offset, limit, signal);
  } catch (error) {
    // A remembered cursor of an older index build (rebuilt meanwhile) is a 400: forget this
    // search's cursors and walk again once.
    if (offset > 0 && error instanceof ApiError && error.status === 400) {
      cursors.delete(searchKey(runId, keywords));
      return indexPage(runId, keywords, offset, limit, signal);
    }
    throw error;
  }
}

async function indexPage(
  runId: string,
  keywords: readonly string[],
  offset: number,
  limit: number,
  signal?: AbortSignal,
): Promise<RawPage> {
  const key = searchKey(runId, keywords);
  let cursor: string | null = null;
  if (offset > 0) {
    cursor = await cursorAt(runId, keywords, offset, signal);
    if (cursor === null) {
      return {
        rows: [],
        total: offset,
        offset,
        backend: "index",
        hasMore: false,
        truncated: false,
        elapsedMs: 0,
      };
    }
  }
  const nextKey = `${key}\u0000${offset + limit}`;
  const request = postQuery(runId, keywords, cursor, limit, offset, signal);
  const named = request.then((payload) => {
    const returned = Array.isArray(payload.matches) ? payload.matches.length : 0;
    const next = nextCursorOf(payload);
    remember(key, offset + returned, next);
    if (returned !== limit) throw new Error("short page");
    return next;
  });
  const settle = () => {
    if (pending.get(nextKey) === named) pending.delete(nextKey);
  };
  // Handles the rejection too (a failed page only makes its waiters walk).
  named.then(settle, settle);
  pending.set(nextKey, named);
  const payload = await request;
  const rows = (Array.isArray(payload.matches) ? payload.matches : []).filter(
    (row): row is RawRow => typeof row === "object" && row !== null,
  );
  const hasMore = nextCursorOf(payload) !== null;
  const truncated = payload.truncated === true;
  return {
    rows,
    // Like v1: exact only once the search reached the end (no next page, no budget stop).
    total: hasMore || truncated ? null : offset + rows.length,
    offset,
    backend: "index",
    hasMore,
    truncated,
    elapsedMs: typeof payload.elapsed_ms === "number" ? payload.elapsed_ms : 0,
    meta: { searchIndex: "ready" },
  };
}
