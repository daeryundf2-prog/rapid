// Analysis jobs (plan analysis-workbench-p1 §3.1): run carving / VSC / NTFS meta / OCR /
// memory import / cross-case correlation from the console and page their result rows.

import type { ServerSort, ServerSortState } from "../contracts/collection";
import { api } from "./client";
import { type RawPage, type RawRow, sortStateOf } from "./collections";

const enc = encodeURIComponent;

/** API kinds (§3.2). */
export type AnalysisKind =
  | "carve"
  | "vsc-discover"
  | "vsc-compare"
  | "vsc-extract"
  | "ntfs-meta"
  | "ocr-batch"
  | "memory-import"
  | "cross-case";

export const ANALYSIS_KINDS: readonly AnalysisKind[] = [
  "carve",
  "vsc-discover",
  "vsc-compare",
  "vsc-extract",
  "ntfs-meta",
  "ocr-batch",
  "memory-import",
  "cross-case",
];

export function isAnalysisKind(value: unknown): value is AnalysisKind {
  return typeof value === "string" && (ANALYSIS_KINDS as readonly string[]).includes(value);
}

export type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface AnalysisProgress {
  done: number;
  total: number | null;
  unit: string;
  message: string;
  percent: number | null;
}

export interface AnalysisState {
  analysis_id: string;
  kind: AnalysisKind | string;
  status: AnalysisStatus;
  options: Record<string, unknown>;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  elapsed_s?: number | null;
  progress: AnalysisProgress;
  row_count: number;
  output_dir?: string;
  summary?: Record<string, unknown>;
  /** Korean error text (failed / cancelled). */
  error?: string | null;
}

export function isAnalysisActive(state: Pick<AnalysisState, "status"> | null | undefined): boolean {
  return state?.status === "queued" || state?.status === "running";
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** Defensive normalisation: a partial state from an older/newer server never crashes the UI. */
export function normalizeAnalysis(raw: unknown): AnalysisState | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const id = typeof r.analysis_id === "string" ? r.analysis_id : null;
  if (!id) return null;
  const p = (r.progress && typeof r.progress === "object" ? r.progress : {}) as Record<string, unknown>;
  const status = ["queued", "running", "completed", "failed", "cancelled"].includes(String(r.status))
    ? (r.status as AnalysisStatus)
    : "queued";
  return {
    analysis_id: id,
    kind: typeof r.kind === "string" ? r.kind : "",
    status,
    options: r.options && typeof r.options === "object" ? (r.options as Record<string, unknown>) : {},
    created_at: typeof r.created_at === "string" ? r.created_at : "",
    started_at: typeof r.started_at === "string" ? r.started_at : null,
    finished_at: typeof r.finished_at === "string" ? r.finished_at : null,
    elapsed_s: asNumber(r.elapsed_s),
    progress: {
      done: asNumber(p.done) ?? 0,
      total: asNumber(p.total),
      unit: typeof p.unit === "string" ? p.unit : "",
      message: typeof p.message === "string" ? p.message : "",
      percent: asNumber(p.percent),
    },
    row_count: asNumber(r.row_count) ?? 0,
    output_dir: typeof r.output_dir === "string" ? r.output_dir : undefined,
    summary: r.summary && typeof r.summary === "object" ? (r.summary as Record<string, unknown>) : {},
    error: typeof r.error === "string" && r.error ? r.error : null,
  };
}

/** `GET /api/runs/{run}/analyses` (newest first). */
export async function listAnalyses(runId: string, signal?: AbortSignal): Promise<AnalysisState[]> {
  const payload = await api<{ analyses?: unknown }>(`/api/runs/${enc(runId)}/analyses`, { signal });
  const list = Array.isArray(payload.analyses) ? payload.analyses : [];
  return list.map(normalizeAnalysis).filter((a): a is AnalysisState => a !== null);
}

export async function getAnalysis(runId: string, id: string, signal?: AbortSignal): Promise<AnalysisState> {
  const raw = await api<unknown>(`/api/runs/${enc(runId)}/analyses/${enc(id)}`, { signal });
  const state = normalizeAnalysis(raw);
  if (!state) throw new Error("분석 상태를 읽을 수 없습니다");
  return state;
}

export interface AnalysisCreated {
  analysis_id: string;
  kind: string;
  status: AnalysisStatus;
}

/** `POST /api/runs/{run}/analyses` → 202 `{analysis_id, kind, status: "queued"}`. */
export function startAnalysis(
  runId: string,
  kind: AnalysisKind,
  options: Record<string, unknown>,
): Promise<AnalysisCreated> {
  return api<AnalysisCreated>(`/api/runs/${enc(runId)}/analyses`, {
    method: "POST",
    body: JSON.stringify({ kind, options }),
  });
}

export async function cancelAnalysis(runId: string, id: string): Promise<AnalysisState | null> {
  const raw = await api<unknown>(`/api/runs/${enc(runId)}/analyses/${enc(id)}/cancel`, {
    method: "POST",
    body: JSON.stringify({}),
  });
  return normalizeAnalysis(raw);
}

export interface AnalysisRowsQuery {
  offset: number;
  limit: number;
  sort?: ServerSort;
  locate?: number;
  pathContains?: string;
  /** 특이사항 filters (`flag=` repeated, `flag_grade=`). */
  flags?: string[];
  flagGrade?: string;
  /** Exact `details` filters (`source=` / `signature_kind=` / `recovery_method=`, repeated). */
  detailFilters?: Record<string, string[]>;
}

/** `details` keys the rows API filters exactly (R3 §3.3); any other key stays a client column filter. */
export const ANALYSIS_DETAIL_FILTER_KEYS: readonly string[] = ["source", "signature_kind", "recovery_method"];

interface RowsPayload {
  rows?: unknown;
  artifacts?: unknown;
  total?: unknown;
  record_count?: unknown;
  has_more?: unknown;
  pagination?: {
    has_more?: unknown;
    scanned?: unknown;
    truncated?: unknown;
    filtered?: unknown;
    matched?: unknown;
  };
  matched?: unknown;
  sort?: unknown;
  sort_supported?: unknown;
}

export function analysisRowsUrl(runId: string, id: string, query: AnalysisRowsQuery): string {
  const params = new URLSearchParams();
  if (query.offset) params.set("offset", String(query.offset));
  params.set("limit", String(query.limit));
  if (query.pathContains?.trim()) params.set("path_contains", query.pathContains.trim());
  for (const flag of query.flags ?? []) params.append("flag", flag);
  if (query.flagGrade) params.set("flag_grade", query.flagGrade);
  for (const [key, values] of Object.entries(query.detailFilters ?? {})) {
    if (ANALYSIS_DETAIL_FILTER_KEYS.includes(key)) for (const value of values) params.append(key, value);
  }
  if (query.sort) {
    params.set("sort", query.sort.key);
    params.set("order", query.sort.order);
    if (query.locate !== undefined) params.set("locate", String(query.locate));
  }
  return `/api/runs/${enc(runId)}/analyses/${enc(id)}/rows?${params}`;
}

function rowsOf(payload: RowsPayload): RawRow[] {
  const list = Array.isArray(payload.rows)
    ? payload.rows
    : Array.isArray(payload.artifacts)
      ? payload.artifacts
      : [];
  return list as RawRow[];
}

/**
 * One window of an analysis job's result rows (same page shape as one artifact kind:
 * `rows`, `record_count`, `record_index`, `sort{…}`). Rows carry `_index` = `record_index`
 * (the rows.jsonl line), so locators survive sorting and path filtering.
 */
export async function fetchAnalysisRowsPage(
  runId: string,
  id: string,
  query: AnalysisRowsQuery,
  signal?: AbortSignal,
): Promise<RawPage> {
  const started = performance.now();
  const payload = await api<RowsPayload>(analysisRowsUrl(runId, id, query), { signal });
  const sortState: ServerSortState | undefined = query.sort ? sortStateOf(payload, query.sort) : undefined;
  const rows =
    sortState?.status === "building"
      ? []
      : rowsOf(payload).map((row, i) => {
          const index =
            typeof row.record_index === "number" &&
            Number.isInteger(row.record_index) &&
            row.record_index >= 0
              ? row.record_index
              : query.offset + i;
          return { ...row, _index: index, _analysis: id };
        });
  const hasMore = payload.pagination?.has_more === true || payload.has_more === true;
  // A path-filtered page counts matches as it scans: the total is known only on the last page.
  const filtered = payload.pagination?.filtered === true;
  const matched = asNumber(payload.matched ?? payload.pagination?.matched);
  const total = filtered
    ? (matched ?? (hasMore ? null : query.offset + rows.length))
    : (asNumber(payload.total) ?? asNumber(payload.record_count));
  return {
    rows,
    total: filtered ? total : (total ?? rows.length),
    offset: query.offset,
    backend: "file",
    truncated: payload.pagination?.truncated === true,
    hasMore,
    ...(filtered ? { meta: { matched } } : {}),
    scanned: asNumber(payload.pagination?.scanned) ?? undefined,
    elapsedMs: Math.round(performance.now() - started),
    ...(sortState ? { sort: sortState } : {}),
  };
}

/** Sorted position of one record (`locate=` → `sort.position`), like `locateArtifactRow`. */
export async function locateAnalysisRow(
  runId: string,
  id: string,
  sort: ServerSort,
  recordIndex: number,
  signal?: AbortSignal,
): Promise<{ status: ServerSortState["status"]; position: number | null }> {
  const payload = await api<RowsPayload>(
    analysisRowsUrl(runId, id, { offset: 0, limit: 1, sort, locate: recordIndex }),
    { signal },
  );
  const state = sortStateOf(payload, sort);
  const raw =
    payload.sort && typeof payload.sort === "object"
      ? (payload.sort as Record<string, unknown>).position
      : null;
  const position = typeof raw === "number" && Number.isInteger(raw) && raw >= 0 ? raw : null;
  return { status: state.status, position: state.status === "ready" ? position : null };
}
