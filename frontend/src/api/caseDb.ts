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
  /** When anyone last changed any field of the mark. */
  updated_at: string;
  /** Who last changed any field (server value; "" / "web-ui" / "local-user" = 이름 없음) and when it was made (F13). */
  reviewer?: string;
  created_at?: string;
  /** Who set the current verdict (status) and when; "" when the mark has none (P2-1). */
  status_by?: string;
  status_at?: string;
  /** Times the mark changed (its history versions). */
  change_count?: number;
  /** The mark's version token: a write sends it back as `expected_version` (F14). */
  version?: number;
  /** File targets: the copy's modification time (a file has no event time). */
  file_modified_at?: string;
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
}

/** Read-only; never creates the case DB. */
export function getReviewMap(runId: string, signal?: AbortSignal): Promise<ReviewMapPayload> {
  return api<ReviewMapPayload>(`/api/runs/${encodeURIComponent(runId)}/review-map`, { signal });
}

/** One write to a mark after the version the console sent: who, when, which fields (review P3-4). */
export interface ConflictChange {
  version: number;
  actor: string;
  changed_at: string;
  /** `status` · `note` · `tags` · `include_in_report` … (never `reviewer`). */
  fields: string[];
}

/** The stored mark a 409 `review-conflict` reports (F14). */
export interface ConflictMark {
  /** false: no mark (never made, or cleared). */
  exists: boolean;
  status: string;
  include_in_report: boolean;
  note: string;
  tags: string[];
  /** Who last changed any field, and when (also set for a cleared mark). */
  reviewer: string;
  updated_at: string;
  /** Who set the current verdict and when ("" when none). */
  status_by: string;
  status_at: string;
  /** Its version token: send it as `expected_version` to overwrite it (0 for no mark). */
  version: number;
  /** The writes since the version the console sent, newest first. */
  changes: ConflictChange[];
}

/** One target of a refused write: its mark changed after the console read it; nothing was written. */
export interface ReviewConflict {
  target_type: string;
  target_id: string;
  /** The version the refused write expected (absent when it sent none). */
  expected_version?: number;
  /** Run-output locator of a located target (echoed back so the console finds its row). */
  collection?: string;
  kind?: string;
  locator?: string;
  current: ConflictMark;
}

function isRecordLike(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The conflicts of a 409 `{code:"review-conflict", conflicts}` detail; null for any other error. */
export function reviewConflictsOf(detail: unknown): ReviewConflict[] | null {
  if (!isRecordLike(detail) || detail.code !== "review-conflict" || !Array.isArray(detail.conflicts))
    return null;
  const text = (value: unknown) => (typeof value === "string" ? value : "");
  const count = (value: unknown) => (typeof value === "number" && Number.isInteger(value) ? value : 0);
  return detail.conflicts.filter(isRecordLike).map((raw) => {
    const current = isRecordLike(raw.current) ? raw.current : {};
    const changes = Array.isArray(current.changes) ? current.changes.filter(isRecordLike) : [];
    return {
      target_type: text(raw.target_type),
      target_id: text(raw.target_id),
      ...(typeof raw.expected_version === "number" ? { expected_version: raw.expected_version } : {}),
      ...(typeof raw.collection === "string" ? { collection: raw.collection } : {}),
      ...(typeof raw.kind === "string" ? { kind: raw.kind } : {}),
      ...(typeof raw.locator === "string" ? { locator: raw.locator } : {}),
      current: {
        exists: current.exists === true,
        status: text(current.status) || "unreviewed",
        include_in_report: current.include_in_report === true,
        note: text(current.note),
        tags: Array.isArray(current.tags) ? current.tags.map(String) : [],
        reviewer: text(current.reviewer),
        updated_at: text(current.updated_at),
        status_by: text(current.status_by),
        status_at: text(current.status_at),
        version: count(current.version),
        changes: changes.map((change) => ({
          version: count(change.version),
          actor: text(change.actor),
          changed_at: text(change.changed_at),
          fields: Array.isArray(change.fields) ? change.fields.map(String) : [],
        })),
      },
    };
  });
}
