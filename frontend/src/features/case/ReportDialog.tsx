import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { getReviewCounts } from "../../api/caseDb";
import { ErrorText } from "./ErrorText";
import {
  EXPORT_ACTIONS,
  type ExportKind,
  exportDisabledReason,
  performExport,
  type ReportFormat,
} from "./exports";
import { Modal } from "./Modal";
import { ReasonButton } from "./ReasonButton";

const FORMATS: Array<{ id: ReportFormat; label: string }> = [
  { id: "html", label: "HTML" },
  { id: "docx", label: "Word (docx)" },
  { id: "pdf", label: "PDF" },
  { id: "md", label: "Markdown" },
];

export function ReportDialog({
  runId,
  runIsActive,
  onClose,
  onNotice,
}: {
  runId: string | null;
  runIsActive: boolean;
  onClose: () => void;
  onNotice?: (message: string) => void;
}) {
  const [format, setFormat] = useState<ReportFormat>("html");
  const [title, setTitle] = useState("");
  const [caseNumber, setCaseNumber] = useState("");
  const [investigator, setInvestigator] = useState("");
  const counts = useQuery({
    queryKey: ["review-counts", runId],
    queryFn: () => getReviewCounts(runId as string),
    enabled: Boolean(runId),
    retry: false,
  });
  const exportMutation = useMutation({
    mutationFn: (kind: ExportKind) =>
      performExport(kind, runId as string, { format, meta: { title, caseNumber, investigator } }),
    onSuccess: (name) => onNotice?.(`${name} 파일을 저장했습니다.`),
  });

  return (
    <Modal title="보고서 내보내기" onClose={onClose}>
      <p>
        보고 후보 {counts.data ? `${counts.data.report_candidates.toLocaleString("ko-KR")}건` : "확인 중"}
      </p>
      <div className="case-field">
        <label htmlFor="report-title">보고서 제목 (선택)</label>
        <input id="report-title" type="text" value={title} onChange={(e) => setTitle(e.target.value)} />
        <label htmlFor="report-case-number">사건 번호 (선택)</label>
        <input
          id="report-case-number"
          type="text"
          value={caseNumber}
          onChange={(e) => setCaseNumber(e.target.value)}
        />
        <label htmlFor="report-investigator">분석관 (선택)</label>
        <input
          id="report-investigator"
          type="text"
          value={investigator}
          onChange={(e) => setInvestigator(e.target.value)}
        />
        <label htmlFor="report-format">보고서 형식</label>
        <select id="report-format" value={format} onChange={(e) => setFormat(e.target.value as ReportFormat)}>
          {FORMATS.map((f) => (
            <option key={f.id} value={f.id}>
              {f.label}
            </option>
          ))}
        </select>
      </div>
      {exportMutation.error && (
        <ErrorText>
          {exportMutation.error instanceof Error ? exportMutation.error.message : "내보내지 못했습니다."}
        </ErrorText>
      )}
      <ul className="case-check-list" aria-label="내보내기 항목">
        {EXPORT_ACTIONS.map((action) => (
          <li key={action.kind}>
            <ReasonButton
              reason={
                exportDisabledReason(action, {
                  runId,
                  runIsActive,
                  reportCandidates: counts.data?.report_candidates,
                }) ?? (exportMutation.isPending ? "내보내는 중입니다" : undefined)
              }
              onClick={() => exportMutation.mutate(action.kind)}
            >
              {action.label} 내보내기
            </ReasonButton>
          </li>
        ))}
      </ul>
    </Modal>
  );
}
