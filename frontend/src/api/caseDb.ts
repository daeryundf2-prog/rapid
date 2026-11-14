import { api } from "./client";

/** `GET /api/runs/{id}/review-counts` (read-only; never creates the case DB). */
export interface ReviewCounts {
  run_id: string;
  database: string;
  case_id: string;
  exists: boolean;
  by_status: Record<string, number>;
  include_in_report: number;
  case_json: { bookmarks: number; include_in_report: number };
  /** The one report-candidate count (report, manifest, bundle agree); `null` with `error`. */
  report_candidates: number | null;
  /** The 5,000-mark cap left case DB marks out of the report. */
  truncated?: boolean;
  error?: { code: string; message: string } | null;
  report_candidates_detail?: {
    count: number | null;
    case_db: number;
    case_json: number;
    truncated: boolean;
    case_db_marks_total: number;
    case_db_mark_limit: number;
  };
}

/** "보고 후보 n건" text of a review-counts answer (cap and read error named, never hidden). */
export function reportCandidatesText(counts: ReviewCounts): string {
  if (counts.report_candidates == null) return counts.error?.message ?? "확인할 수 없음";
  const base = `${counts.report_candidates.toLocaleString("ko-KR")}건`;
  const detail = counts.report_candidates_detail;
  if (!counts.truncated || !detail) return base;
  return `${base} (케이스 DB 표시 ${detail.case_db_marks_total.toLocaleString("ko-KR")}건 중 최근 ${detail.case_db_mark_limit.toLocaleString("ko-KR")}건만 반영)`;
}

export function getReviewCounts(runId: string): Promise<ReviewCounts> {
  return api<ReviewCounts>(`/api/runs/${encodeURIComponent(runId)}/review-counts`);
}

export interface EnsureCaseDbResult {
  database: string;
  case_id: string;
  imported: boolean;
}

/** `POST /api/runs/{id}/case-db/ensure` — imports the run into its default case DB once. */
export function ensureCaseDb(runId: string): Promise<EnsureCaseDbResult> {
  return api<EnsureCaseDbResult>(`/api/runs/${encodeURIComponent(runId)}/case-db/ensure`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export interface SavedSearch {
  name: string;
  keywords?: string[];
  limit?: number;
  sources?: string[];
  created_at?: string;
  [key: string]: unknown;
}

/** `POST /api/case-db/saved-searches/list` — `CaseDbSavedSearchListRequest`. */
export async function listSavedSearches(database: string, caseId: string): Promise<SavedSearch[]> {
  const payload = await api<{ saved_searches: SavedSearch[] }>("/api/case-db/saved-searches/list", {
    method: "POST",
    body: JSON.stringify({ database, case_id: caseId }),
  });
  return Array.isArray(payload.saved_searches) ? payload.saved_searches : [];
}

/** `POST /api/case-db/saved-searches` — `CaseDbSavedSearchRequest`. */
export function saveSearch(body: {
  database: string;
  case_id: string;
  name: string;
  keywords: string[];
  limit?: number;
  sources?: string[];
  created_by?: string;
}): Promise<unknown> {
  return api("/api/case-db/saved-searches", { method: "POST", body: JSON.stringify(body) });
}

/** One case-DB review mark with its run-output locator (`GET /api/runs/{id}/review-map`). */
export interface ReviewMapMark {
  citation_id: string;
  target_type: string;
  target_id: string;
  status: string;
  tags: string[];
  note: string;
  include_in_report: boolean;
  updated_at: string;
  /** Grid collection + artifact kind + locator; empty when the row has no run-output locator. */
  collection: string;
  kind: string;
  locator: string;
  /** Source row's display label (analysis rows: the row title), when the server knows it. */
  label?: string;
  title?: string;
  path?: string;
  preview?: string;
  timestamp?: string;
  target_kind?: string;
}

export interface ReviewMapPayload {
  run_id: string;
  database: string;
  case_id: string;
  exists: boolean;
  marks: ReviewMapMark[];
  truncated: boolean;
  /** Set (with empty `marks`) when the case DB could not be read; the marks are then unknown. */
  error?: string;
}

/** Read-only; never creates the case DB. */
export function getReviewMap(runId: string, signal?: AbortSignal): Promise<ReviewMapPayload> {
  return api<ReviewMapPayload>(`/api/runs/${encodeURIComponent(runId)}/review-map`, { signal });
}
