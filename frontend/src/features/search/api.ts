// Search index API (plan search-2026-10-13 §3.2): index status and build, one result page,
// one search's count.

import { type AnalysisState, normalizeAnalysis } from "../../api/analyses";
import { api } from "../../api/client";
import type { RawRow } from "../../api/collections";

const enc = encodeURIComponent;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function numberOf(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

const INDEX_STATES = ["none", "building", "ready", "stale", "corrupt", "build-failed-swap"] as const;
export type SearchIndexState = (typeof INDEX_STATES)[number];

export interface SearchIndexStatus {
  readonly state: SearchIndexState;
  readonly docCount: number;
  /** Why the index is stale, unreadable or could not be replaced (server sentence). */
  readonly reason: string | null;
  /** The running build (progress and cancel target). */
  readonly building: AnalysisState | null;
}

/** `GET /search/index`. */
export async function getSearchIndexStatus(runId: string, signal?: AbortSignal): Promise<SearchIndexStatus> {
  const raw = await api<unknown>(`/api/runs/${enc(runId)}/search/index`, { signal });
  const body = isRecord(raw) ? raw : {};
  const reason = [body.stale_reason, body.corrupt_reason, body.swap_error].find(
    (value): value is string => typeof value === "string" && value !== "",
  );
  return {
    state: INDEX_STATES.find((state) => state === body.status) ?? "none",
    docCount: numberOf(body.doc_count) ?? 0,
    reason: reason ?? null,
    building: normalizeAnalysis(body.building),
  };
}

/** `POST /search/index/build`: queue a full build (409 while one runs). */
export async function buildSearchIndex(runId: string): Promise<AnalysisState | null> {
  const raw = await api<unknown>(`/api/runs/${enc(runId)}/search/index/build`, {
    method: "POST",
    body: JSON.stringify({ mode: "full" }),
  });
  return normalizeAnalysis(raw);
}

export interface SearchIndexPage {
  readonly rows: RawRow[];
  /** Resumes after this page; null on the last page. */
  readonly nextCursor: string | null;
  readonly elapsedMs: number;
  readonly truncated: boolean;
  /** Server notes on the query and the index (short terms scan, a stale index, cut rows). */
  readonly warnings: readonly string[];
}

/**
 * `POST /search/query` for rows only (`aggregates: false`): the server stops at the first
 * `limit` matches, so a broad search answers as fast as a narrow one. Totals come from
 * `countSearch`.
 */
export async function querySearchIndex(
  runId: string,
  request: { readonly q: string; readonly limit: number; readonly cursor?: string },
  signal?: AbortSignal,
): Promise<SearchIndexPage> {
  const raw = await api<unknown>(`/api/runs/${enc(runId)}/search/query`, {
    method: "POST",
    body: JSON.stringify({
      q: request.q,
      aggregates: false,
      page: { limit: request.limit, ...(request.cursor ? { cursor: request.cursor } : {}) },
    }),
    signal,
  });
  const body = isRecord(raw) ? raw : {};
  const page = isRecord(body.page) ? body.page : {};
  const parsed = isRecord(body.query) && isRecord(body.query.parsed) ? body.query.parsed : {};
  return {
    rows: Array.isArray(body.rows) ? body.rows.filter(isRecord) : [],
    nextCursor: typeof page.next_cursor === "string" && page.next_cursor ? page.next_cursor : null,
    elapsedMs: numberOf(body.elapsed_ms) ?? 0,
    truncated: body.truncated === true,
    warnings: Array.isArray(parsed.warnings) ? parsed.warnings.map(String) : [],
  };
}

export interface SearchCount {
  /** null: the server's time budget ended before the search was counted. */
  readonly count: number | null;
  /** false: the count stopped at the server's cap. */
  readonly exact: boolean;
  /** Matches per forensic domain (the tree's domain ids), largest first. */
  readonly byDomain: ReadonlyArray<readonly [domain: string, count: number]>;
  /** Server sentence when the search text is not a valid query. */
  readonly error: string | null;
}

/** `POST /search/count` for one search. */
export async function countSearch(runId: string, q: string, signal?: AbortSignal): Promise<SearchCount> {
  const raw = await api<unknown>(`/api/runs/${enc(runId)}/search/count`, {
    method: "POST",
    body: JSON.stringify({ terms: [{ q }] }),
    signal,
  });
  const items = isRecord(raw) && Array.isArray(raw.items) ? raw.items : [];
  const item = isRecord(items[0]) ? items[0] : {};
  const domains = isRecord(item.by_domain) ? item.by_domain : {};
  return {
    count: numberOf(item.count),
    exact: item.count_exact !== false,
    byDomain: Object.entries(domains)
      .flatMap(([domain, value]): Array<readonly [string, number]> => {
        const count = numberOf(value);
        return count === null ? [] : [[domain, count]];
      })
      .sort((a, b) => b[1] - a[1]),
    error: typeof item.error === "string" ? item.error : null,
  };
}
