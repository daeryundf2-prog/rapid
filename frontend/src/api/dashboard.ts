/**
 * 접수 dashboard API (S7, plan §9 X1/X2/X17):
 * `GET /api/runs/{id}/dashboard` (profile keywords, evidence source + partitions,
 * export history) and `GET|PUT /api/runs/{id}/case-notes` (examiner + case summary,
 * stored in `<output_dir>/rapidtriage-case-notes.json`, fills the report's 분석자/범위).
 */

import { api } from "./client";

const run = (runId: string) => `/api/runs/${encodeURIComponent(runId)}`;

export interface EvidencePartition {
  number: number;
  description: string;
  /** `filesystem_guess` from mmls (ntfs, fat32, …; "unknown"). */
  filesystem: string;
  size_bytes: number | null;
  start_sector: number | null;
  byte_offset: number | null;
  /** Partition the run recovered files from. */
  selected: boolean;
  recommended: boolean;
}

export interface EvidenceSource {
  path: string;
  name: string;
  /** "image" (E01/raw/virtual disk stage output) | "file" | "folder". */
  kind: "image" | "file" | "folder" | string;
  image_output: string | null;
  size_bytes: number | null;
  partitions: EvidencePartition[];
  selected_partition: number | null;
}

export interface ExportEntry {
  name: string;
  /** "case-report" | "reviewer-bundle" | "submission-manifest" | "validation-package" | "extract". */
  type: string;
  label: string;
  created_at: string | null;
  size: number | null;
  status: string;
  item_count?: number | null;
  download_url: string;
}

export interface RunDashboard {
  run_id: string;
  completed: boolean;
  profile: { mode: string; description: string; keywords: string[] };
  evidence_source: EvidenceSource;
  exports: ExportEntry[];
}

/** Fills missing blocks so cards never read through `undefined` (older servers, partial payloads). */
export function normalizeDashboard(
  runId: string,
  raw: Partial<RunDashboard> | null | undefined,
): RunDashboard {
  const source: Partial<EvidenceSource> = raw?.evidence_source ?? {};
  return {
    run_id: raw?.run_id ?? runId,
    completed: raw?.completed === true,
    profile: {
      mode: raw?.profile?.mode ?? "",
      description: raw?.profile?.description ?? "",
      keywords: Array.isArray(raw?.profile?.keywords) ? raw.profile.keywords : [],
    },
    evidence_source: {
      path: source.path ?? "",
      name: source.name ?? "",
      kind: source.kind ?? "folder",
      image_output: source.image_output ?? null,
      size_bytes: typeof source.size_bytes === "number" ? source.size_bytes : null,
      partitions: Array.isArray(source.partitions) ? source.partitions : [],
      selected_partition: source.selected_partition ?? null,
    },
    exports: Array.isArray(raw?.exports) ? raw.exports : [],
  };
}

export async function getRunDashboard(runId: string): Promise<RunDashboard> {
  return normalizeDashboard(runId, await api<Partial<RunDashboard>>(`${run(runId)}/dashboard`));
}

export interface CaseNotes {
  run_id?: string;
  examiner: string;
  summary: string;
  updated_at: string | null;
  exists: boolean;
}

export async function getCaseNotes(runId: string): Promise<CaseNotes> {
  const raw = await api<Partial<CaseNotes>>(`${run(runId)}/case-notes`);
  return {
    run_id: raw?.run_id ?? runId,
    examiner: typeof raw?.examiner === "string" ? raw.examiner : "",
    summary: typeof raw?.summary === "string" ? raw.summary : "",
    updated_at: raw?.updated_at ?? null,
    exists: raw?.exists === true,
  };
}

export function saveCaseNotes(
  runId: string,
  notes: { examiner: string; summary: string },
): Promise<CaseNotes> {
  return api<CaseNotes>(`${run(runId)}/case-notes`, { method: "PUT", body: JSON.stringify(notes) });
}

/** Match count for one keyword (`/search?keyword=…&limit=N`); `capped` when the limit was hit. */
export async function getKeywordHitCount(
  runId: string,
  keyword: string,
  limit: number,
  signal?: AbortSignal,
): Promise<{ count: number; capped: boolean }> {
  const params = new URLSearchParams({ keyword, limit: String(limit) });
  const payload = await api<{ summary?: { match_count?: number }; matches?: unknown[] }>(
    `${run(runId)}/search?${params}`,
    { signal },
  );
  const count =
    typeof payload.summary?.match_count === "number"
      ? payload.summary.match_count
      : Array.isArray(payload.matches)
        ? payload.matches.length
        : 0;
  return { count, capped: count >= limit };
}
