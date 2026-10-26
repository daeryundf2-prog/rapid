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

export function getSubmissionManifest(runId: string, includeAll = false, maxItems = 500) {
  return api<Record<string, unknown>>(
    `${run(runId)}/submission-manifest?include_all=${includeAll}&max_items=${maxItems}`,
  );
}

export const submissionManifestFile = (runId: string) => `${run(runId)}/submission-manifest/file`;
/** Read-only GET of the manifest the last GET wrote (no rewrite, no second audit record). */
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
