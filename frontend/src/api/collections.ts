// Collection fetchers for the single DataGrid (console-redesign S3).
//
// Each fetcher returns a RawPage: raw API rows plus the paging/backend facts the
// grid footer shows. Mapping raw rows to GridRow lives in
// features/grid/columns/<collection>.ts so the API layer stays shape-agnostic.

import type { CollectionQuery } from "../contracts/collection";
import { api } from "./client";
import { type ArtifactsQuery, artifactsQueryString } from "./runs";

export type RawRow = Record<string, unknown>;

export interface RawPage {
  rows: RawRow[];
  /** null when the backend cannot tell (never for the paged JSON outputs). */
  total: number | null;
  offset: number;
  backend: string;
  truncated: boolean;
  elapsedMs: number;
  /** More rows exist after this page (needed when `total` is null). */
  hasMore?: boolean;
  /** Rows scanned by a server-side filter. */
  scanned?: number;
  /** Artifact kinds the page was drawn from when a category restricted them (category nodes). */
  kinds?: string[];
}

const enc = encodeURIComponent;

function now(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

function asRows(value: unknown): RawRow[] {
  return Array.isArray(value) ? (value as RawRow[]) : [];
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

async function jsonPaged(
  runId: string,
  endpoint: "files" | "docs" | "timeline" | "indicators",
  key: string,
  offset: number,
  limit: number,
  signal?: AbortSignal,
): Promise<RawPage> {
  const started = now();
  const payload = await api<Record<string, unknown>>(
    `/api/runs/${enc(runId)}/${endpoint}?offset=${offset}&limit=${limit}`,
    { signal },
  );
  const rows = asRows(payload[key]);
  return {
    rows,
    total: asNumber(payload.total) ?? rows.length,
    offset,
    backend: "file",
    truncated: false,
    elapsedMs: Math.round(now() - started),
  };
}

export const fetchFilesPage = (runId: string, offset: number, limit: number, signal?: AbortSignal) =>
  jsonPaged(runId, "files", "candidates", offset, limit, signal);
export const fetchDocsPage = (runId: string, offset: number, limit: number, signal?: AbortSignal) =>
  jsonPaged(runId, "docs", "results", offset, limit, signal);
export const fetchTimelinePage = (runId: string, offset: number, limit: number, signal?: AbortSignal) =>
  jsonPaged(runId, "timeline", "events", offset, limit, signal);
export const fetchIndicatorsPage = (runId: string, offset: number, limit: number, signal?: AbortSignal) =>
  jsonPaged(runId, "indicators", "indicators", offset, limit, signal);

interface ArtifactKindPage {
  artifacts?: unknown;
  total?: unknown;
  record_count?: unknown;
  has_more?: unknown;
  pagination?: { has_more?: unknown; scanned?: unknown; truncated?: unknown; filtered?: unknown };
}

async function artifactWindow(
  runId: string,
  query: ArtifactsQuery,
  signal?: AbortSignal,
): Promise<Record<string, ArtifactKindPage>> {
  const payload = await api<{ artifacts?: Record<string, ArtifactKindPage> }>(
    `/api/runs/${enc(runId)}/artifacts?${artifactsQueryString({ ...query, offset: query.offset || undefined })}`,
    { signal },
  );
  return payload.artifacts ?? {};
}

function kindTotal(page: ArtifactKindPage): number | null {
  const direct = asNumber(page.total) ?? asNumber(page.record_count);
  if (direct !== null) return direct;
  return page.pagination?.filtered === true ? null : asRows(page.artifacts).length;
}

const countsCache = new Map<string, { at: number; counts: [string, number][] }>();
const COUNTS_TTL_MS = 30_000;

/** Per-kind record counts (sorted by kind), via a limit=1 probe; cached briefly. */
async function artifactKindCounts(runId: string, signal?: AbortSignal): Promise<[string, number][]> {
  const cached = countsCache.get(runId);
  if (cached && Date.now() - cached.at < COUNTS_TTL_MS) return cached.counts;
  const window = await artifactWindow(runId, { limit: 1 }, signal);
  const counts = Object.keys(window)
    .sort()
    .map((kind): [string, number] => [kind, kindTotal(window[kind] as ArtifactKindPage) ?? 0]);
  countsCache.set(runId, { at: Date.now(), counts });
  return counts;
}

export function resetArtifactCountsCache(): void {
  countsCache.clear();
}

function pageFlags(pages: ArtifactKindPage[]) {
  return {
    hasMore: pages.some((p) => p.pagination?.has_more === true || p.has_more === true),
    truncated: pages.some((p) => p.pagination?.truncated === true),
    scanned: pages.reduce((sum, p) => sum + (asNumber(p.pagination?.scanned) ?? 0), 0) || undefined,
  };
}

/**
 * One window of the artifacts collection. A single kind = one `kind=` request
 * (server pages only that kind). `pathContains` is the server-side path filter:
 * offset then counts matches and `total` is null unless the kind was fully scanned.
 * Rows carry `_kind` and `_index` (the kind-local row index when unfiltered; with a
 * filter it is the match ordinal and the real pointer is not known to the API).
 *
 * `restrictKinds` (category nodes, no `kind`) narrows the run's kinds — it gets
 * the run's kind list and returns the kinds to page; the page reports them in `kinds`.
 */
export async function fetchArtifactsPage(
  runId: string,
  kind: string | undefined,
  offset: number,
  limit: number,
  signal?: AbortSignal,
  pathContains?: string,
  restrictKinds?: (available: readonly string[]) => string[],
): Promise<RawPage> {
  const started = now();
  const filter = pathContains?.trim() || undefined;
  if (!kind && restrictKinds) {
    return fetchArtifactKindsPage(runId, restrictKinds, offset, limit, signal, filter, started);
  }
  if (kind) {
    const window = await artifactWindow(
      runId,
      { kind: [kind], offset, limit, path_contains: filter },
      signal,
    );
    const page = window[kind];
    if (!page) return { rows: [], total: 0, offset, backend: "file", truncated: false, elapsedMs: 0 };
    const rows = asRows(page.artifacts).map((row, i) => ({ ...row, _kind: kind, _index: offset + i }));
    return {
      rows,
      total: kindTotal(page),
      offset,
      backend: "file",
      ...pageFlags([page]),
      elapsedMs: Math.round(now() - started),
    };
  }
  if (filter) {
    // All kinds + path filter: per-kind matches from the first window only.
    const window = await artifactWindow(runId, { offset: 0, limit, path_contains: filter }, signal);
    const rows: RawRow[] = [];
    for (const k of Object.keys(window).sort()) {
      for (const [i, row] of asRows(window[k]?.artifacts).entries())
        rows.push({ ...row, _kind: k, _index: i });
    }
    const flags = pageFlags(Object.values(window));
    return {
      rows,
      total: offset === 0 ? rows.length : null,
      offset,
      backend: "file",
      hasMore: false,
      truncated: flags.truncated || flags.hasMore,
      scanned: flags.scanned,
      elapsedMs: Math.round(now() - started),
    };
  }
  const counts = await artifactKindCounts(runId, signal);
  const { rows, total } = await pageAcrossKinds(runId, counts, offset, limit, signal);
  return { rows, total, offset, backend: "file", truncated: false, elapsedMs: Math.round(now() - started) };
}

/** Concatenate kinds in `counts` order and fetch the [offset, offset+limit) window (one `kind=` request per kind touched). */
async function pageAcrossKinds(
  runId: string,
  counts: [string, number][],
  offset: number,
  limit: number,
  signal?: AbortSignal,
): Promise<{ rows: RawRow[]; total: number }> {
  const total = counts.reduce((sum, [, n]) => sum + n, 0);
  const rows: RawRow[] = [];
  let base = 0;
  for (const [k, n] of counts) {
    const start = Math.max(offset, base);
    const end = Math.min(offset + limit, base + n);
    if (end > start) {
      const local = start - base;
      const window = await artifactWindow(runId, { kind: [k], offset: local, limit: end - start }, signal);
      for (const [i, row] of asRows(window[k]?.artifacts).entries()) {
        rows.push({ ...row, _kind: k, _index: local + i });
      }
    }
    base += n;
    if (base >= offset + limit) break;
  }
  return { rows, total };
}

/** Category window: page across the kinds `restrict` keeps (one `kind=` per kind, or repeated `kind=` with a path filter). */
async function fetchArtifactKindsPage(
  runId: string,
  restrict: (available: readonly string[]) => string[],
  offset: number,
  limit: number,
  signal: AbortSignal | undefined,
  filter: string | undefined,
  started: number,
): Promise<RawPage> {
  const all = await artifactKindCounts(runId, signal);
  const allowed = new Set(restrict(all.map(([k]) => k)));
  const counts = all.filter(([k]) => allowed.has(k));
  const kinds = counts.map(([k]) => k);
  if (kinds.length === 0) {
    return { rows: [], total: 0, offset, backend: "file", truncated: false, elapsedMs: 0, kinds };
  }
  if (filter) {
    // Path filter: one request with every category kind (repeatable kind=), first window only.
    const window = await artifactWindow(
      runId,
      { kind: kinds, offset: 0, limit, path_contains: filter },
      signal,
    );
    const rows: RawRow[] = [];
    for (const k of kinds) {
      for (const [i, row] of asRows(window[k]?.artifacts).entries())
        rows.push({ ...row, _kind: k, _index: i });
    }
    const flags = pageFlags(Object.values(window));
    return {
      rows,
      total: offset === 0 ? rows.length : null,
      offset,
      backend: "file",
      hasMore: false,
      truncated: flags.truncated || flags.hasMore,
      scanned: flags.scanned,
      elapsedMs: Math.round(now() - started),
      kinds,
    };
  }
  const { rows, total } = await pageAcrossKinds(runId, counts, offset, limit, signal);
  return {
    rows,
    total,
    offset,
    backend: "file",
    truncated: false,
    elapsedMs: Math.round(now() - started),
    kinds,
  };
}

/** Unified search (FTS when the run has a case DB, else a bounded scan). Not paged by the API. */
export async function fetchSearchRows(
  runId: string,
  query: Pick<CollectionQuery, "search" | "extension">,
  limit: number,
  signal?: AbortSignal,
): Promise<RawPage> {
  const spec = query.search;
  if (!spec || spec.keywords.length === 0) {
    return { rows: [], total: 0, offset: 0, backend: "none", truncated: false, elapsedMs: 0 };
  }
  const params = new URLSearchParams();
  for (const keyword of spec.keywords) params.append("keyword", keyword);
  params.set("limit", String(Math.min(limit, 1000)));
  params.set("search_mode", spec.mode);
  for (const source of spec.sources ?? []) params.append("source", source);
  for (const extension of query.extension ?? []) params.append("extension", extension);
  if (spec.hideKnownGood) params.set("hide_known_good", "true");
  const payload = await api<Record<string, unknown>>(`/api/runs/${enc(runId)}/search?${params}`, { signal });
  const rows = asRows(payload.matches);
  return {
    rows,
    total: rows.length,
    offset: 0,
    backend: typeof payload.backend === "string" ? payload.backend : "scan",
    truncated: payload.truncated === true,
    elapsedMs: asNumber(payload.elapsed_ms) ?? 0,
  };
}

/**
 * Review board = the run's case-DB review marks (GET /review-map, canonical store)
 * followed by any case.json bookmarks (fallback store when no case DB could be
 * created). Whole collection, client paged. Rows carry `_store`.
 */
export async function fetchReviewRows(runId: string, signal?: AbortSignal): Promise<RawPage> {
  const started = now();
  const [map, casePayload] = await Promise.all([
    api<{ marks?: unknown; truncated?: unknown }>(`/api/runs/${enc(runId)}/review-map`, { signal }),
    api<{ exists?: boolean; case?: { bookmarks?: unknown } | null }>(`/api/runs/${enc(runId)}/case`, {
      signal,
    }).catch(() => ({ case: null })),
  ]);
  const rows = [
    ...asRows(map.marks).map((row) => ({ ...row, _store: "case-db" })),
    ...asRows(casePayload.case?.bookmarks).map((row) => ({ ...row, _store: "bookmarks" })),
  ];
  return {
    rows,
    total: rows.length,
    offset: 0,
    backend: "case-db",
    truncated: map.truncated === true,
    elapsedMs: Math.round(now() - started),
  };
}

export async function fetchOutputRows(runId: string, signal?: AbortSignal): Promise<RawPage> {
  const started = now();
  const payload = await api<{ files?: unknown }>(`/api/runs/${enc(runId)}/output-files`, { signal });
  const rows = asRows(payload.files);
  return {
    rows,
    total: rows.length,
    offset: 0,
    backend: "file",
    truncated: false,
    elapsedMs: Math.round(now() - started),
  };
}

// ---- review / bookmark / extract actions ---------------------------------

export interface CaseDbHandle {
  database: string;
  case_id: string;
}

/** POST /api/runs/{id}/case-db/ensure — the run's canonical case DB (created/imported once). */
export function ensureCaseDb(runId: string): Promise<CaseDbHandle> {
  return api<CaseDbHandle>(`/api/runs/${enc(runId)}/case-db/ensure`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export interface ReviewMarkBody {
  status?: string;
  verification_status?: string;
  include_in_report?: boolean;
  /** Replaces the row's tags. */
  tags?: string[];
  /** Merged into the row's existing tags (server side). */
  add_tags?: string[];
  note?: string;
}

/** A case-db row, or a run-output locator the server resolves against `run_id`. */
export type ReviewBatchTarget =
  | { target_type: string; target_id: string }
  | { collection: string; kind?: string; locator: string };

export function postReviewBatch(
  handle: CaseDbHandle,
  targets: ReviewBatchTarget[],
  mark: ReviewMarkBody,
  runId?: string,
): Promise<{ updated_count?: number }> {
  return api("/api/case-db/review-batch", {
    method: "POST",
    body: JSON.stringify({
      database: handle.database,
      case_id: handle.case_id,
      ...(runId ? { run_id: runId } : {}),
      targets,
      reviewer: "web-ui",
      ...mark,
    }),
  });
}

export interface BookmarkBody {
  /** Output alias: files | docs | timeline | indicators | artifacts:<kind>. */
  source: string;
  /** JSON pointer inside that output, e.g. /candidates/894. */
  pointer: string;
  tags?: string[];
  note?: string;
  review_status?: string;
  include_in_report?: boolean;
}

export function postBookmark(runId: string, body: BookmarkBody): Promise<unknown> {
  return api(`/api/runs/${enc(runId)}/bookmarks`, { method: "POST", body: JSON.stringify(body) });
}
