/**
 * 접수 dashboard API (S7, plan §9 X1/X2/X17):
 * `GET /api/runs/{id}/dashboard` (profile keywords, evidence source + partitions,
 * export history) and `GET|PUT /api/runs/{id}/case-notes` (examiner + case summary,
 * stored in `<output_dir>/rapidtriage-case-notes.json`, fills the report's 분석자/범위).
 */

import { api } from "./client";

const run = (runId: string) => `/api/runs/${encodeURIComponent(runId)}`;

export interface EvidencePartition {
  /** 1-based row position in the partition table (unique; older servers omit it). */
  index?: number;
  /** Partition number for display (0 is valid for GPT slot 0). */
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
  /** Read-only GET of the saved file (404 until an export POST wrote it). */
  download_url: string;
  /** Extract without its zip yet: POST this first, then download (GETs never write). */
  build_url?: string | null;
}

/** Write the missing zip of an extract (`POST …/extract/{name}/zip`) before downloading it. */
export function buildExportFile(buildUrl: string): Promise<unknown> {
  return api<unknown>(buildUrl, { method: "POST" });
}

/**
 * Processing scope on four axes (R8 T-023, `rapidtriage/api/app/run_scope.py`). Never one number:
 * partitions · allocated · deleted · unallocated. Percentages are floored server-side (shown as-is).
 * `basis` "inferred" = derived from extraction stats before a Sleuth Kit comparison;
 * "unavailable" = no stats (folder evidence, older results).
 */
export interface RunScope {
  basis: "inferred" | "measured" | "unavailable" | string;
  partitions: { total: number | null; supported: number | null; processed: number | null };
  allocated: { listed_pct: number | null; content_pct: number | null; basis?: string };
  deleted: {
    records: number | null;
    attempted: number | null;
    attempted_pct: number | null;
    listed_pct: number | null;
    not_attempted?: number | null;
  };
  unallocated: { scanned_pct: number | null; measured: boolean };
  caps: { code: string; limit?: number; reached?: boolean; skipped?: number; axis?: string }[];
  partial: boolean | null;
  notes: string[];
}

export interface RunDashboard {
  run_id: string;
  completed: boolean;
  profile: { mode: string; description: string; keywords: string[] };
  evidence_source: EvidenceSource;
  exports: ExportEntry[];
  /** Four-axis processing scope (T-023); null when the server predates it. */
  scope: RunScope | null;
}

function normalizeScope(raw: unknown): RunScope | null {
  if (!raw || typeof raw !== "object") return null;
  const value = raw as Partial<RunScope>;
  if (typeof value.basis !== "string") return null;
  return {
    basis: value.basis,
    partitions: { total: null, supported: null, processed: null, ...value.partitions },
    allocated: { listed_pct: null, content_pct: null, ...value.allocated },
    deleted: { records: null, attempted: null, attempted_pct: null, listed_pct: null, ...value.deleted },
    unallocated: { scanned_pct: null, measured: false, ...value.unallocated },
    caps: Array.isArray(value.caps) ? value.caps : [],
    partial: typeof value.partial === "boolean" ? value.partial : null,
    notes: Array.isArray(value.notes) ? value.notes.filter((note) => typeof note === "string") : [],
  };
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
    scope: normalizeScope(raw?.scope),
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
