import { api } from "./client";

/** `POST /api/runs/{id}/extract` body — `RunExtractRequest` (max 500 rows). */
export interface RunExtractBody {
  rows: Array<{ path: string; locator?: string | null }>;
  /** Letters, digits, '.', '_', '-' (max 64); a timestamp is always appended. */
  output_name?: string | null;
}

export interface ExtractEntry {
  original_path: string;
  extracted_path: string;
  relative_path: string;
  sha256: string;
  modified_at: string;
  size: number;
}

/** Response: the extract manifest plus `name` and `download_url` (zip, built lazily, max 2 GB). */
export interface RunExtractResult {
  command: "extract";
  output_dir: string;
  safety: { read_only: boolean; max_extract_size_bytes: number; max_file_count: number };
  summary: { input_count: number; selected_count: number; extracted_count: number; skipped_count: number };
  entries: ExtractEntry[];
  /** e.g. reason "read-only" | "max-file-count" | "max-extract-size" | "missing" | "destination-exists". */
  skipped: Array<{ original_path: string; reason: string }>;
  name: string;
  download_url: string;
}

/** 403 when any path is outside the run's allowed source roots; 422 for 0 or >500 rows. */
export function extractRows(runId: string, body: RunExtractBody): Promise<RunExtractResult> {
  return api<RunExtractResult>(`/api/runs/${encodeURIComponent(runId)}/extract`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}
