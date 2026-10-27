import { api, downloadFile } from "./client";

const run = (runId: string) => `/api/runs/${encodeURIComponent(runId)}`;

/** `POST /api/runs/{id}/case-report` — `CaseReportCreateRequest`. */
export interface CaseReportBody {
  template?: string;
  title?: string | null;
  case_number?: string | null;
  investigator?: string | null;
  organization?: string | null;
  requester?: string | null;
  scope?: string | null;
  conclusion?: string | null;
  include_all?: boolean;
  max_items?: number;
  /**
   * Optional report sections to include (R7 AI 사용: `ai-usage`, the AI usage section of 갈래 C);
   * sent only for a run with AI usage rows, absent = the server's default sections.
   */
  sections?: string[];
}

export function createCaseReport(runId: string, body: CaseReportBody = {}) {
  return api<{ report_path: string; exports: Record<string, unknown> }>(`${run(runId)}/case-report`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export const caseReportFile = (runId: string, format?: string) =>
  `${run(runId)}/case-report/file${format ? `/${format}` : ""}`;

/** `POST /api/runs/{id}/reviewer-bundle` — `ReviewerBundleCreateRequest`. */
export function createReviewerBundle(
  runId: string,
  body: { title?: string | null; include_all?: boolean; max_items?: number } = {},
) {
  return api<Record<string, unknown>>(`${run(runId)}/reviewer-bundle`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export const reviewerBundleFile = (runId: string) => `${run(runId)}/reviewer-bundle/file`;

/** `POST /api/runs/{id}/submission-manifest` — writes manifest + audit once (R-4 backend). */
export interface SubmissionManifestWrite {
  /** Every file the call wrote (manifest, audit). */
  written?: string[];
  /** Read-only GET of the saved manifest (`/submission-manifest/saved`). */
  download_url?: string;
}

export function writeSubmissionManifest(runId: string, includeAll = false, maxItems = 500) {
  return api<SubmissionManifestWrite>(
    `${run(runId)}/submission-manifest?include_all=${includeAll}&max_items=${maxItems}`,
    { method: "POST" },
  );
}
/** Read-only GET of the manifest the last POST wrote (no rewrite, no second audit record). */
export const savedSubmissionManifestFile = (runId: string) => `${run(runId)}/submission-manifest/saved`;

/** `POST /api/runs/{id}/validation-package` — writes package + audit into the run folder (r7 L4). */
export interface ValidationPackageWrite {
  package_path: string;
  audit: string;
  /** Every file the call wrote. */
  written: string[];
  /** Read-only GET of the saved package (no second write). */
  download_url: string;
}

export function writeValidationPackage(runId: string) {
  return api<ValidationPackageWrite>(`${run(runId)}/validation-package`, { method: "POST" });
}

/** Read-only: the package the last export wrote (404 before one exists). */
export const savedValidationPackageFile = (runId: string) => `${run(runId)}/validation-package/saved`;

export { downloadFile };
