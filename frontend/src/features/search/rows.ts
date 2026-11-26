/**
 * Pages of the search grid. A search runs on the run's index when it can (first rows without
 * waiting for totals, then cursor pages); a run without a usable index, or an option only the
 * scan has, gets the bounded scan of the run outputs, one response cut into grid pages.
 */

import { ApiError, api } from "../../api/client";
import type { RawPage, RawRow } from "../../api/collections";
import type { CollectionQuery } from "../../contracts/collection";
import { useSearchActivity } from "./activity";
import { querySearchIndex } from "./api";
import { searchPlan } from "./queryModel";

type SearchPageQuery = Pick<CollectionQuery, "search" | "extension" | "offset" | "limit">;
type SearchSpec = NonNullable<CollectionQuery["search"]>;

const enc = encodeURIComponent;
/** Rows one scan response may hold (API limit). */
const SCAN_LIMIT = 1000;
/** Rows one index request may hold (API limit). */
const INDEX_LIMIT = 1000;

function isRecord(value: unknown): value is RawRow {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Cursor that resumes an index search at a row offset, per run and query. */
const cursors = new Map<string, Map<number, string>>();

/** Forget every cursor: a rebuilt index does not accept the old ones. */
export function resetSearchCursors(): void {
  cursors.clear();
}

/** One index page and the server's notes on the query. */
async function indexPage(
  runId: string,
  q: string,
  query: SearchPageQuery,
  signal: AbortSignal | undefined,
): Promise<{ readonly page: RawPage; readonly warnings: readonly string[] }> {
  const key = `${runId}\u0000${q}`;
  const known = cursors.get(key) ?? new Map<number, string>();
  cursors.set(key, known);
  let position = 0;
  let cursor: string | undefined;
  for (const [offset, value] of known) {
    if (offset <= query.offset && offset > position) {
      position = offset;
      cursor = value;
    }
  }
  // Pages load in order, so the cursor is normally known; after a reset, walk up to the offset.
  while (position < query.offset) {
    const skipped = await querySearchIndex(
      runId,
      { q, limit: Math.min(INDEX_LIMIT, query.offset - position), cursor },
      signal,
    );
    if (!skipped.nextCursor || skipped.rows.length === 0) {
      const total = position + skipped.rows.length;
      const { truncated, elapsedMs, warnings } = skipped;
      return {
        page: { rows: [], total, offset: query.offset, backend: "index", truncated, elapsedMs },
        warnings,
      };
    }
    position += skipped.rows.length;
    cursor = skipped.nextCursor;
    known.set(position, cursor);
  }
  const page = await querySearchIndex(runId, { q, limit: query.limit, cursor }, signal);
  const end = query.offset + page.rows.length;
  const hasMore = page.nextCursor !== null && page.rows.length === query.limit;
  if (page.nextCursor) known.set(end, page.nextCursor);
  return {
    page: {
      rows: page.rows,
      // The last page fixes the total; before that it comes from the count request.
      total: hasMore ? null : end,
      offset: query.offset,
      backend: "index",
      truncated: page.truncated,
      elapsedMs: page.elapsedMs,
      hasMore,
    },
    warnings: page.warnings,
  };
}

/** The last scan response: one scan answers every grid page of its search. */
let lastScan: { readonly url: string; readonly response: Promise<RawPage> } | null = null;

function scanUrl(runId: string, spec: SearchSpec, extensions: readonly string[]): string {
  const params = new URLSearchParams();
  for (const keyword of spec.keywords) params.append("keyword", keyword);
  params.set("limit", String(SCAN_LIMIT));
  params.set("search_mode", spec.mode);
  for (const source of spec.sources ?? []) params.append("source", source);
  for (const extension of extensions) params.append("extension", extension);
  if (spec.hideKnownGood) params.set("hide_known_good", "true");
  return `/api/runs/${enc(runId)}/search?${params}`;
}

async function scanAll(url: string, signal: AbortSignal | undefined): Promise<RawPage> {
  const payload = await api<Record<string, unknown>>(url, { signal });
  const rows = Array.isArray(payload.matches) ? payload.matches.filter(isRecord) : [];
  return {
    rows,
    total: rows.length,
    offset: 0,
    backend: typeof payload.backend === "string" ? payload.backend : "scan",
    truncated: payload.truncated === true,
    elapsedMs: typeof payload.elapsed_ms === "number" ? payload.elapsed_ms : 0,
  };
}

async function scanPage(
  runId: string,
  spec: SearchSpec,
  query: SearchPageQuery,
  signal: AbortSignal | undefined,
): Promise<RawPage> {
  const url = scanUrl(runId, spec, query.extension ?? []);
  // The first page asks the server; the later ones cut the same response.
  if (query.offset === 0 || lastScan?.url !== url) lastScan = { url, response: scanAll(url, signal) };
  const all = await lastScan.response;
  return { ...all, rows: all.rows.slice(query.offset, query.offset + query.limit), offset: query.offset };
}

function isMissingIndex(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 404 || error.status === 409);
}

/** One grid page of the search collection. */
export async function fetchSearchPage(
  runId: string,
  query: SearchPageQuery,
  signal?: AbortSignal,
): Promise<RawPage> {
  const spec = query.search;
  if (!spec || spec.keywords.length === 0) {
    return { rows: [], total: 0, offset: 0, backend: "none", truncated: false, elapsedMs: 0 };
  }
  const plan = searchPlan(spec, query.extension);
  const activity = query.offset === 0 ? useSearchActivity.getState() : null;
  try {
    if (plan.kind === "index") {
      activity?.begin("index", null);
      try {
        const { page, warnings } = await indexPage(runId, plan.q, query, signal);
        activity?.arrive("index", warnings);
        return page;
      } catch (error) {
        // No usable index (none yet, or unreadable): the bounded scan still answers.
        if (!isMissingIndex(error)) throw error;
      }
    }
    activity?.begin("scan", plan.kind === "scan" ? plan.reason : null);
    const page = await scanPage(runId, spec, query, signal);
    activity?.arrive("scan", []);
    return page;
  } catch (error) {
    activity?.settle();
    throw error;
  }
}
