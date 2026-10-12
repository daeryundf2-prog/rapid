/**
 * Why an image has no OCR text when the 처리 stage already ran an OCR batch over it: the
 * preview only reuses successful batch rows (routes_media.stored_ocr_sidecar), so a failed
 * row — or a batch that failed as a whole (no OCR engine) — would otherwise read as "no
 * sidecar". Looks at the run's newest ocr-batch job that covered the image.
 */

import { type AnalysisState, fetchAnalysisRowsPage, listAnalyses } from "../../../api/analyses";

export interface OcrFailure {
  analysisId: string;
  /** Korean reason (row `error`, else the job's `error`). */
  reason: string;
  /** The whole batch failed (vs. this image's row). */
  batch: boolean;
  finishedAt: string | null;
}

const norm = (path: string) => path.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();

/** The job targeted this image: listed in its resolved paths / locators, or all media images. */
function covers(job: AnalysisState, path: string): boolean {
  const options = job.options ?? {};
  const resolved = Array.isArray(options.resolved_paths) ? options.resolved_paths : null;
  if (resolved?.length) return resolved.some((p) => typeof p === "string" && norm(p) === norm(path));
  const target =
    options.target && typeof options.target === "object" ? (options.target as Record<string, unknown>) : {};
  if (target.kind === "media-image") return true;
  const locators = Array.isArray(target.locators) ? target.locators : [];
  return locators.some((p) => typeof p === "string" && norm(p) === norm(path));
}

export async function latestOcrFailure(
  runId: string,
  path: string,
  signal?: AbortSignal,
): Promise<OcrFailure | null> {
  const jobs = await listAnalyses(runId, signal);
  for (const job of jobs) {
    if (job.kind !== "ocr-batch") continue;
    if (job.status === "failed") {
      if (!covers(job, path)) continue;
      return {
        analysisId: job.analysis_id,
        reason: job.error || "OCR 일괄 작업이 실패했습니다",
        batch: true,
        finishedAt: job.finished_at ?? null,
      };
    }
    if (job.status !== "completed" && job.status !== "cancelled") continue;
    const page = await fetchAnalysisRowsPage(
      runId,
      job.analysis_id,
      { offset: 0, limit: 20, pathContains: path.split(/[\\/]/).pop() || path },
      signal,
    );
    const row = page.rows.find((r) => {
      const d = (r.details ?? {}) as Record<string, unknown>;
      const source =
        typeof d.source_path === "string" ? d.source_path : typeof r.path === "string" ? r.path : "";
      return source && norm(source) === norm(path);
    });
    if (!row) continue;
    const d = (row.details ?? {}) as Record<string, unknown>;
    // The newest batch that read this image decides: a success there means no failure to show.
    if (d.status !== "failed") return null;
    return {
      analysisId: job.analysis_id,
      reason: typeof d.error === "string" && d.error ? d.error : "OCR에 실패했습니다",
      batch: false,
      finishedAt: job.finished_at ?? null,
    };
  }
  return null;
}
