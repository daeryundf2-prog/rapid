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
  report_candidates: number;
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
}

/** Read-only; never creates the case DB. */
export function getReviewMap(runId: string, signal?: AbortSignal): Promise<ReviewMapPayload> {
  return api<ReviewMapPayload>(`/api/runs/${encodeURIComponent(runId)}/review-map`, { signal });
}
