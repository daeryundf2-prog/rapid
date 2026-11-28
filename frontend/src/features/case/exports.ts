import { create } from "zustand";
import {
  caseReportFile,
  createCaseReport,
  createReviewerBundle,
  downloadFile,
  getSubmissionManifest,
  getValidationPackage,
  reviewerBundleFile,
  submissionManifestFile,
  validationPackageFile,
} from "../../api/reports";

export type ExportKind = "case-report" | "reviewer-bundle" | "submission-manifest" | "validation-package";

export interface ExportAction {
  kind: ExportKind;
  commandId: string;
  label: string;
  /** Needs at least one include-in-report row (plan 4.3: "보고 후보 0건"). */
  needsCandidates: boolean;
  /** One line: who the file is for and what is in it (보고 page, F16). */
  audience: string;
}

export const EXPORT_ACTIONS: ExportAction[] = [
  {
    kind: "case-report",
    commandId: "export.case-report",
    label: "보고서",
    needsCandidates: true,
    audience:
      "보고 수신자(검사·수사관)용: 보고서에 포함한 항목과 근거를 문서 하나로 (HTML·Word·PDF·Markdown)",
  },
  {
    kind: "reviewer-bundle",
    commandId: "export.reviewer-bundle",
    label: "리뷰어 번들",
    needsCandidates: true,
    audience: "다른 검수자용: 포함 항목과 원본 근거 파일을 ZIP 하나로, 같은 판정을 다시 확인할 때",
  },
  {
    kind: "submission-manifest",
    commandId: "export.submission-manifest",
    label: "제출 매니페스트",
    needsCandidates: true,
    audience: "제출 담당자용: 제출하는 항목과 그 해시 목록 (JSON)",
  },
  {
    kind: "validation-package",
    commandId: "export.validation-package",
    label: "검증 패키지",
    needsCandidates: false,
    audience: "처리 검증용: 이 런의 처리 과정·도구·해시 기록 (JSON), 보고 항목이 없어도 만듭니다",
  },
];

export type ReportFormat = "md" | "html" | "docx" | "pdf";

export interface ReportMeta {
  title: string;
  caseNumber: string;
  investigator: string;
}

export const NO_CANDIDATES_REASON =
  "보고서에 포함한 항목이 0건입니다. 검토 보드에서 행의 ⋯ 메뉴(행 메뉴) › ‘보고서 포함 표시’로 넣으세요";

export function exportDisabledReason(
  action: ExportAction,
  state: { runId: string | null; runIsActive: boolean; reportCandidates: number | undefined },
): string | undefined {
  if (!state.runId) return "열린 케이스가 없습니다";
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

/** Run one export and download its file; resolves with the saved file name (recorded in the history). */
export async function performExport(
  kind: ExportKind,
  runId: string,
  options: { format?: ReportFormat; meta?: Partial<ReportMeta> } = {},
): Promise<string> {
  const fileName = await runExport(kind, runId, options);
  const label = EXPORT_ACTIONS.find((action) => action.kind === kind)?.label ?? kind;
  useExportHistory.getState().add({ runId, kind, label, fileName, at: new Date().toISOString() });
  return fileName;
}

async function runExport(
  kind: ExportKind,
  runId: string,
  options: { format?: ReportFormat; meta?: Partial<ReportMeta> },
): Promise<string> {
  switch (kind) {
    case "case-report": {
      const format = options.format ?? "html";
      const meta = options.meta ?? {};
      await createCaseReport(runId, {
        template: "legal-handoff",
        title: meta.title?.trim() || null,
        case_number: meta.caseNumber?.trim() || null,
        investigator: meta.investigator?.trim() || null,
        include_all: false,
        max_items: 500,
      });
      return downloadFile(caseReportFile(runId, format), `case-report.${format}`);
    }
    case "reviewer-bundle":
      await createReviewerBundle(runId, { include_all: false, max_items: 500 });
      return downloadFile(reviewerBundleFile(runId), "reviewer-bundle.zip");
    case "submission-manifest":
      await getSubmissionManifest(runId, false, 500);
      return downloadFile(submissionManifestFile(runId), "submission-manifest.json");
    case "validation-package":
      await getValidationPackage(runId);
      return downloadFile(validationPackageFile(runId), "validation-package.json");
  }
}
