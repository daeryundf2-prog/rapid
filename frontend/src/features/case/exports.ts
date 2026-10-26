import { create } from "zustand";
import { ApiError } from "../../api/client";
import {
  caseReportFile,
  createCaseReport,
  createReviewerBundle,
  downloadFile,
  getSubmissionManifest,
  reviewerBundleFile,
  savedSubmissionManifestFile,
  savedValidationPackageFile,
  submissionManifestFile,
  writeValidationPackage,
} from "../../api/reports";
import { NO_RUN_REASON } from "../../commands/reasons";
import { joinRunPath } from "./WriteConfirm";

export type ExportKind = "case-report" | "reviewer-bundle" | "submission-manifest" | "validation-package";

export interface ExportAction {
  kind: ExportKind;
  commandId: string;
  label: string;
  /** Needs at least one include-in-report row (plan 4.3: "보고 후보 0건"). */
  needsCandidates: boolean;
}

export const EXPORT_ACTIONS: ExportAction[] = [
  { kind: "case-report", commandId: "export.case-report", label: "보고서", needsCandidates: true },
  {
    kind: "reviewer-bundle",
    commandId: "export.reviewer-bundle",
    label: "리뷰어 번들",
    needsCandidates: true,
  },
  {
    kind: "submission-manifest",
    commandId: "export.submission-manifest",
    label: "제출 매니페스트",
    needsCandidates: true,
  },
  {
    kind: "validation-package",
    commandId: "export.validation-package",
    label: "검증 패키지",
    needsCandidates: false,
  },
];

export type ReportFormat = "md" | "html" | "docx" | "pdf";

export interface ReportMeta {
  title: string;
  caseNumber: string;
  investigator: string;
}

export const NO_CANDIDATES_REASON = "보고 후보 0건 — 표시된 항목이 없습니다";

export function exportDisabledReason(
  action: ExportAction,
  state: { runId: string | null; runIsActive: boolean; reportCandidates: number | undefined },
): string | undefined {
  if (!state.runId) return NO_RUN_REASON;
  if (state.runIsActive) return "실행이 끝난 뒤에 내보낼 수 있습니다";
  if (action.needsCandidates && state.reportCandidates === 0) return NO_CANDIDATES_REASON;
  return undefined;
}

export interface ExportRecord {
  runId: string;
  kind: ExportKind;
  label: string;
  fileName: string;
  at: string;
}

/** Exports made in this session, newest first (보고 stage "내보내기 이력"). */
export const useExportHistory = create<{ records: ExportRecord[]; add: (record: ExportRecord) => void }>(
  (set) => ({
    records: [],
    add: (record) => set((s) => ({ records: [record, ...s.records].slice(0, 50) })),
  }),
);

/** Every file `POST /case-report` writes (server CASE_REPORT_EXPORTS + its audit record). */
export const CASE_REPORT_FILES: Array<{ format: ReportFormat | null; what: string; name: string }> = [
  { format: "md", what: "보고서 원본(Markdown)", name: "rapidtriage-case-report.md" },
  { format: "html", what: "보고서 HTML", name: "rapidtriage-case-report.html" },
  { format: "docx", what: "보고서 Word(docx)", name: "rapidtriage-case-report.docx" },
  { format: "pdf", what: "보고서 PDF", name: "rapidtriage-case-report.pdf" },
  { format: null, what: "형식별 해시 목록(JSON)", name: "rapidtriage-case-report.exports.json" },
  { format: null, what: "감사 기록", name: "rapidtriage-case-report.audit.md" },
];

/**
 * Files an export writes into the run folder (server helpers default_*_path), shown in the export
 * dialog before anything is sent (r7 L4) and named again in the completion toast.
 */
export function exportWrites(
  kind: ExportKind,
  folder: string | null,
  format: ReportFormat = "html",
): Array<{ what: string; where: string }> {
  switch (kind) {
    case "case-report":
      // R-4: the server writes every format plus its export manifest and the audit record
      // (core/case_report.py CASE_REPORT_EXPORTS + audit_path_for), whatever format is chosen.
      return CASE_REPORT_FILES.map((file) => ({
        what: file.format === format ? `${file.what} (선택 형식 — 다운로드 폴더에도 저장)` : file.what,
        where: joinRunPath(folder, file.name),
      }));
    case "reviewer-bundle":
      return [
        {
          what: "리뷰어 번들 폴더·ZIP (다운로드 폴더에도 저장)",
          where: joinRunPath(folder, "rapidtriage-reviewer-bundle"),
        },
      ];
    case "submission-manifest":
      return [
        {
          what: "제출 매니페스트(JSON) (다운로드 폴더에도 저장)",
          where: joinRunPath(folder, "rapidtriage-submission-manifest.json"),
        },
        { what: "감사 기록", where: joinRunPath(folder, "rapidtriage-submission-manifest.audit.json") },
      ];
    case "validation-package":
      return [
        {
          what: "검증 패키지(JSON)",
          where: joinRunPath(folder, "rapidforensic-run-validation-package.json"),
        },
        { what: "감사 기록", where: joinRunPath(folder, "rapidforensic-run-validation-package.audit.json") },
      ];
  }
}

export interface ExportResult {
  /** File name saved (download) or written (validation package). */
  fileName: string;
  /** Where the server wrote it (run folder), when it said so. */
  path: string | null;
  /** Read-only re-open of the written file (the toast's 열기). */
  open?: () => Promise<unknown>;
  /** Every file the server wrote (its own list when it sent one, else the known static list). */
  written?: string[];
}

const baseName = (path: string) => path.split(/[\\/]/).pop() || path;

const stringsOf = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === "string" && v.length > 0) : [];

/**
 * Files a `POST /case-report` response says it wrote: its `written` list (backend R-4), else
 * `report_path` + every `exports` value + `audit`; empty when the response names none.
 */
export function caseReportWritten(response: Record<string, unknown> | null | undefined): string[] {
  if (!response) return [];
  const listed = stringsOf(response.written);
  if (listed.length > 0) return listed;
  const exportsMap =
    response.exports && typeof response.exports === "object" ? Object.values(response.exports) : [];
  const all = [response.report_path, ...exportsMap, response.audit].filter(
    (v): v is string => typeof v === "string" && v.length > 0,
  );
  return [...new Set(all)];
}

const folderOf = (path: string) => {
  const cut = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  return cut > 0 ? path.slice(0, cut) : "";
};

/** The completion toast's detail: the folder then every written file name. */
export function writtenDetail(written: string[]): string | null {
  const first = written[0];
  if (!first) return null;
  const folder = folderOf(first);
  const names = written.map(baseName).join(", ");
  return `${folder ? `${folder} — ` : ""}${written.length}개 파일: ${names}`;
}

/** Run one export (after the dialog confirmed it); resolves with what was saved (recorded in the history). */
export async function performExport(
  kind: ExportKind,
  runId: string,
  options: { format?: ReportFormat; meta?: Partial<ReportMeta> } = {},
): Promise<ExportResult> {
  const result = await runExport(kind, runId, options);
  const label = EXPORT_ACTIONS.find((action) => action.kind === kind)?.label ?? kind;
  useExportHistory
    .getState()
    .add({ runId, kind, label, fileName: result.fileName, at: new Date().toISOString() });
  return result;
}

async function runExport(
  kind: ExportKind,
  runId: string,
  options: { format?: ReportFormat; meta?: Partial<ReportMeta> },
): Promise<ExportResult> {
  switch (kind) {
    case "case-report": {
      const format = options.format ?? "html";
      const meta = options.meta ?? {};
      const created = await createCaseReport(runId, {
        template: "legal-handoff",
        title: meta.title?.trim() || null,
        case_number: meta.caseNumber?.trim() || null,
        investigator: meta.investigator?.trim() || null,
        include_all: false,
        max_items: 500,
      });
      const fileName = await downloadFile(caseReportFile(runId, format), `case-report.${format}`);
      const reported = caseReportWritten(created as unknown as Record<string, unknown>);
      const folder = created.report_path ? folderOf(created.report_path) || null : null;
      const written =
        reported.length > 0 ? reported : CASE_REPORT_FILES.map((file) => joinRunPath(folder, file.name));
      return { fileName, path: created.report_path ?? null, written };
    }
    case "reviewer-bundle": {
      const created = await createReviewerBundle(runId, { include_all: false, max_items: 500 });
      const fileName = await downloadFile(reviewerBundleFile(runId), "reviewer-bundle.zip");
      return { fileName, path: typeof created.archive === "string" ? created.archive : null };
    }
    case "submission-manifest": {
      // Written once by the GET; the download re-reads the saved file (`/saved`, backend R-4).
      // A server without `/saved` (404/405) falls back to `/file`, which rewrites it.
      await getSubmissionManifest(runId, false, 500);
      let fileName: string;
      try {
        fileName = await downloadFile(savedSubmissionManifestFile(runId), "submission-manifest.json");
      } catch (error) {
        if (!(error instanceof ApiError) || (error.status !== 404 && error.status !== 405)) throw error;
        fileName = await downloadFile(submissionManifestFile(runId), "submission-manifest.json");
      }
      return { fileName, path: null };
    }
    case "validation-package": {
      // Written once into the run folder (POST); 열기 re-reads the saved file — no second write.
      const written = await writeValidationPackage(runId);
      const fileName = baseName(written.package_path);
      return {
        fileName,
        path: written.package_path,
        open: () => downloadFile(savedValidationPackageFile(runId), fileName),
      };
    }
  }
}
