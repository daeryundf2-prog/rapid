/**
 * 통합 보기 API (axiom-adoption §3.2):
 *   GET /api/runs/{run}/derived                      → set summary (tables, source)
 *   GET /api/runs/{run}/derived/{table}?q&kind&sort&limit&after → keyset page
 *   GET /api/runs/{run}/derived/{table}/rows?value=  → one value's original rows (≤20 samples)
 *   POST /api/runs/{run}/analyses {kind: "derived"}  → build the tables again
 */

import { api } from "../../api/client";

const enc = encodeURIComponent;

export type DerivedTableId = "people" | "devices" | "paths" | "attachments" | "credentials" | "urls";
export const DERIVED_TABLE_IDS: readonly DerivedTableId[] = [
  "people",
  "devices",
  "paths",
  "attachments",
  "credentials",
  "urls",
];

export function isDerivedTable(value: unknown): value is DerivedTableId {
  return typeof value === "string" && (DERIVED_TABLE_IDS as readonly string[]).includes(value);
}

export type DerivedSort = "count" | "first_seen" | "last_seen";

export interface DerivedSource {
  status: string;
  analysis_id: string;
  source: "run-stage" | "analysis" | string;
  generated_at: string | null;
  coverage: "complete" | "partial";
  incomplete_sources?: string[];
  reason?: string;
}

export interface DerivedTableSummary {
  table: DerivedTableId;
  label: string;
  rows: number;
  occurrences: number;
  capped: boolean;
  cap_reason: string | null;
  dropped_values: number;
  by_kind: Record<string, number>;
  by_semantic: Record<string, number>;
  by_class?: Record<string, number>;
}

export interface DerivedMeta {
  run_id: string;
  source: DerivedSource | null;
  reason?: string;
  tables: DerivedTableSummary[];
  url_classes?: { version: string | null; labels: Record<string, string> };
  limitation?: string;
}

export interface DerivedRow {
  value: string;
  normalized: string;
  semantic: string;
  semantics: Record<string, number>;
  count: number;
  kinds: Record<string, number>;
  families: Record<string, number>;
  first_seen: string | null;
  last_seen: string | null;
  sample_count: number;
  url_class?: string | null;
  url_class_label?: string | null;
  /** urls: every occurrence came from URL carving (page file / unallocated strings). */
  carved_only?: boolean;
  examples?: string[];
  length?: number;
  sha256?: string;
}

export interface DerivedPage {
  run_id: string;
  table: DerivedTableId;
  label: string;
  source: DerivedSource;
  total: number;
  matched: number;
  limit: number;
  sort: DerivedSort;
  q: string | null;
  kind: string | null;
  rows: DerivedRow[];
  next_cursor: string | null;
}

export interface DerivedSample {
  kind: string;
  record_index: number;
  field: string;
  family: string;
  artifact_type: string;
  time: string | null;
  collection: "artifacts" | "files" | "analysis";
  locator: string;
  /** files: `candidates` | `inventory`. */
  scope?: string;
  analysis_id?: string;
  /** The analysis job kind of an `analysis:<id>` sample (opens that analysis node). */
  analysis_kind?: string;
}

export interface DerivedValueRows extends Omit<DerivedRow, "sample_count"> {
  run_id: string;
  table: DerivedTableId;
  label: string;
  samples: DerivedSample[];
}

export interface DerivedPageQuery {
  q?: string;
  kind?: string;
  sort?: DerivedSort;
  limit?: number;
  after?: string;
}

export const DERIVED_PAGE_LIMIT = 200;

export function derivedMetaKey(runId: string | null) {
  return ["derived-meta", runId] as const;
}

export function fetchDerivedMeta(runId: string, signal?: AbortSignal): Promise<DerivedMeta> {
  return api<DerivedMeta>(`/api/runs/${enc(runId)}/derived`, { signal });
}

export function derivedPageUrl(runId: string, table: DerivedTableId, query: DerivedPageQuery): string {
  const params = new URLSearchParams();
  if (query.q?.trim()) params.set("q", query.q.trim());
  if (query.kind) params.set("kind", query.kind);
  if (query.sort && query.sort !== "count") params.set("sort", query.sort);
  params.set("limit", String(query.limit ?? DERIVED_PAGE_LIMIT));
  if (query.after) params.set("after", query.after);
  return `/api/runs/${enc(runId)}/derived/${enc(table)}?${params.toString()}`;
}

export function fetchDerivedPage(
  runId: string,
  table: DerivedTableId,
  query: DerivedPageQuery,
  signal?: AbortSignal,
): Promise<DerivedPage> {
  return api<DerivedPage>(derivedPageUrl(runId, table, query), { signal });
}

export function fetchDerivedValueRows(
  runId: string,
  table: DerivedTableId,
  normalized: string,
  signal?: AbortSignal,
): Promise<DerivedValueRows> {
  return api<DerivedValueRows>(
    `/api/runs/${enc(runId)}/derived/${enc(table)}/rows?value=${enc(normalized)}`,
    { signal },
  );
}

/** Start a `derived` analysis (통합 보기 다시 만들기); 202 → `{analysis_id}`. */
export function startDerivedAnalysis(runId: string): Promise<{ analysis_id: string; status: string }> {
  return api(`/api/runs/${enc(runId)}/analyses`, {
    method: "POST",
    body: JSON.stringify({ kind: "derived", options: {} }),
  });
}
