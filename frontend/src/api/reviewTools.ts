/**
 * Review tools API (AXIOM adoption E3, plan §3.3): case tags, tag batches with hash
 * propagation, histogram baselines, mark history, related media and the export context.
 * Server: rapidtriage/api/app/routes_review_tools.py.
 */

import { api } from "./client";
import type { CaseDbHandle, ReviewBatchTarget } from "./collections";

const enc = encodeURIComponent;

/** The eight colour tokens (tokens.css `--tag-1` … `--tag-8`). */
export const TAG_COLOR_TOKENS = [
  "tag-1",
  "tag-2",
  "tag-3",
  "tag-4",
  "tag-5",
  "tag-6",
  "tag-7",
  "tag-8",
] as const;
export type TagColorToken = (typeof TAG_COLOR_TOKENS)[number];

export const TAG_COLOR_LABELS: Record<TagColorToken, string> = {
  "tag-1": "빨강",
  "tag-2": "주황",
  "tag-3": "초록",
  "tag-4": "청록",
  "tag-5": "파랑",
  "tag-6": "보라",
  "tag-7": "자주",
  "tag-8": "회갈색",
};

export interface CaseTag {
  id: number;
  case_id: string;
  name: string;
  /** "system": 북마크 · 우선순위 1–5 (name fixed, not deletable). */
  kind: "user" | "system";
  color_token: TagColorToken;
  shortcut: number | null;
  description: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
  deleted_by: string | null;
  /** Review marks carrying the tag. */
  count: number;
}

export interface CaseTagsPayload {
  case_id: string;
  /** False before the run has a case DB (no tags yet). */
  exists: boolean;
  tags: CaseTag[];
}

const caseUrl = (caseId: string, runId: string, suffix = "") =>
  `/api/cases/${enc(caseId)}/${suffix}${suffix.includes("?") ? "&" : "?"}run_id=${enc(runId)}`;

export function listCaseTags(runId: string, caseId: string, signal?: AbortSignal): Promise<CaseTagsPayload> {
  return api<CaseTagsPayload>(caseUrl(caseId, runId, "tags"), { signal });
}

export interface CaseTagInput {
  name: string;
  color_token: TagColorToken;
  shortcut: number | null;
  description: string;
}

export function createCaseTag(
  runId: string,
  caseId: string,
  body: CaseTagInput & { created_by?: string },
): Promise<{ tag: CaseTag }> {
  return api(caseUrl(caseId, runId, "tags"), { method: "POST", body: JSON.stringify(body) });
}

export function updateCaseTag(
  runId: string,
  caseId: string,
  tagId: number,
  body: Partial<CaseTagInput> & { actor?: string },
): Promise<{ tag: CaseTag }> {
  return api(caseUrl(caseId, runId, `tags/${tagId}`), { method: "PATCH", body: JSON.stringify(body) });
}

export function deleteCaseTag(
  runId: string,
  caseId: string,
  tagId: number,
  actor?: string,
): Promise<{ tag: CaseTag; removed_from_marks: number }> {
  const suffix = `tags/${tagId}${actor ? `?actor=${enc(actor)}` : ""}`;
  return api(caseUrl(caseId, runId, suffix), { method: "DELETE" });
}

export interface TagBatchBody {
  tag_ids?: number[];
  remove_tag_ids?: number[];
  propagate_by_hash?: boolean;
  reviewer?: string;
}

export interface TagBatchResult {
  applied_count: number;
  changed_count: number;
  created_count: number;
  propagation?: {
    hash_values: number;
    matched_file_rows: number;
    added_rows: number;
    hashless_targets: number;
    cap: number;
  };
}

/** `POST /api/case-db/review-batch` with tag ids (and optional same-hash propagation). */
export function postTagBatch(
  handle: CaseDbHandle,
  runId: string,
  targets: ReviewBatchTarget[],
  body: TagBatchBody,
): Promise<TagBatchResult> {
  return api<TagBatchResult>("/api/case-db/review-batch", {
    method: "POST",
    body: JSON.stringify({
      database: handle.database,
      case_id: handle.case_id,
      run_id: runId,
      targets,
      ...body,
    }),
  });
}

// --- histogram ---------------------------------------------------------------

export interface HistogramBar {
  key: string;
  label: string;
  group: "collection" | "artifact";
  count: number;
  baseline_count?: number;
  delta?: number;
}

export interface HistogramBaseline {
  id: number;
  case_id: string;
  name: string;
  run_id: string;
  created_by: string;
  created_at: string;
  category_count: number;
}

export interface RunHistogramPayload {
  run_id: string;
  case_id: string;
  bars: HistogramBar[];
  total: number;
  baseline?: HistogramBaseline;
  baseline_total?: number;
}

export function getRunHistogram(
  runId: string,
  compare?: number | null,
  signal?: AbortSignal,
): Promise<RunHistogramPayload> {
  const query = compare ? `?compare=${compare}` : "";
  return api<RunHistogramPayload>(`/api/runs/${enc(runId)}/histogram${query}`, { signal });
}

export function listHistogramBaselines(
  runId: string,
  caseId: string,
): Promise<{ exists: boolean; baselines: HistogramBaseline[] }> {
  return api(caseUrl(caseId, runId, "histogram-baselines"));
}

export function createHistogramBaseline(
  runId: string,
  caseId: string,
  name: string,
  createdBy?: string,
): Promise<{ baseline: HistogramBaseline }> {
  return api(caseUrl(caseId, runId, "histogram-baselines"), {
    method: "POST",
    body: JSON.stringify({ name, run_id: runId, ...(createdBy ? { created_by: createdBy } : {}) }),
  });
}

// --- history / related media / export context ---------------------------------

export interface ReviewHistoryEntry {
  version: number;
  changed_at: string;
  author: string;
  changed_fields: string[];
  note_before: string;
  note_after: string;
  tags_before: string[];
  tags_after: string[];
  status_before: string;
  status_after: string;
}

export function getReviewHistory(
  runId: string,
  target: { collection: string; kind?: string; locator: string },
  signal?: AbortSignal,
): Promise<{ entries: ReviewHistoryEntry[] }> {
  const params = new URLSearchParams({ collection: target.collection, locator: target.locator });
  if (target.kind) params.set("kind", target.kind);
  return api(`/api/runs/${enc(runId)}/review-history?${params.toString()}`, { signal });
}

export interface RelatedMedia {
  count: number;
  paths: string[];
  source: "case-db" | "duplicate_content_groups" | "none";
  hash_algorithm?: string;
  hash?: string;
}

export function getRelatedMedia(runId: string, path: string, signal?: AbortSignal): Promise<RelatedMedia> {
  return api<RelatedMedia>(`/api/runs/${enc(runId)}/related-media?path=${enc(path)}`, { signal });
}

export interface ExportContext {
  case_id: string;
  case_number: string | null;
  evidence_number: string | null;
  evidence_name: string | null;
}

export function getExportContext(runId: string): Promise<ExportContext> {
  return api<ExportContext>(`/api/runs/${enc(runId)}/export-context`);
}
