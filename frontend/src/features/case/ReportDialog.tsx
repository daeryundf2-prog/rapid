import { useMutation, useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import { getReviewCounts } from "../../api/caseDb";
import { caseLinkOf } from "./caseLink";
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

/**
 * 보고서 내보내기 (review #4): one radio group for what to export, the report's own fields
 * only while 보고서 is chosen, and ONE primary "내보내기" whose single disabled reason is the
 * chosen kind's (보고 후보 0건, 실행 중 …).
 */
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
  const [kind, setKind] = useState<ExportKind>("case-report");
  const [format, setFormat] = useState<ReportFormat>("html");
  const [title, setTitle] = useState("");
  // A case run pre-fills 사건 번호 and 분석자 from its case (AXIOM adoption E1).
  const [caseNumber, setCaseNumber] = useState(() => caseLinkOf(runId)?.caseNumber ?? "");
  const [investigator, setInvestigator] = useState(() => caseLinkOf(runId)?.examiner ?? "");
  const groupId = useId();
  const counts = useQuery({
    queryKey: ["review-counts", runId],
    queryFn: () => getReviewCounts(runId as string),
    enabled: Boolean(runId),
    retry: false,
  });
  const exportMutation = useMutation({
    mutationFn: (chosen: ExportKind) =>
      performExport(chosen, runId as string, { format, meta: { title, caseNumber, investigator } }),
    onSuccess: (name) => onNotice?.(`${name} 파일을 저장했습니다.`),
  });
  const reasonOf = (action: (typeof EXPORT_ACTIONS)[number]) =>
    exportDisabledReason(action, {
      runId,
      runIsActive,
      reportCandidates: counts.data?.report_candidates,
    });
  const chosen = EXPORT_ACTIONS.find((action) => action.kind === kind) ?? EXPORT_ACTIONS[0];
  const reason =
    (chosen ? reasonOf(chosen) : "내보낼 항목을 고르세요") ??
    (exportMutation.isPending ? "내보내는 중입니다" : undefined);

  return (
    <Modal
      title="보고서 내보내기"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="button roomy" onClick={onClose}>
            취소
          </button>
          <ReasonButton
            className="button primary roomy"
            reason={reason}
            data-testid="export-submit"
            onClick={() => exportMutation.mutate(kind)}
          >
            내보내기
          </ReasonButton>
        </>
      }
    >
      <p className="case-help">
        보고 후보 {counts.data ? `${counts.data.report_candidates.toLocaleString("ko-KR")}건` : "확인 중"}
      </p>
      <fieldset className="case-field case-choices">
        <legend id={groupId} className="case-label">
          내보낼 항목
        </legend>
        <div className="case-radio-group">
          {EXPORT_ACTIONS.map((action) => {
            // An unavailable kind stays choosable; its reason is the one shown under 내보내기.
            const why = reasonOf(action);
            return (
              <label key={action.kind} className={`case-option${why ? " is-unavailable" : ""}`} title={why}>
                <input
                  type="radio"
                  name="export-kind"
                  value={action.kind}
                  checked={kind === action.kind}
                  onChange={() => setKind(action.kind)}
                />
                <span>{action.label}</span>
              </label>
            );
          })}
        </div>
      </fieldset>
      {kind === "case-report" ? (
        <>
          <div className="case-field">
            <label className="case-label" htmlFor="report-format">
              보고서 형식
            </label>
            <select
              id="report-format"
              value={format}
              onChange={(e) => setFormat(e.target.value as ReportFormat)}
            >
              {FORMATS.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.label}
                </option>
              ))}
            </select>
          </div>
          <div className="case-field">
            <label className="case-label" htmlFor="report-title">
              보고서 제목 (선택)
            </label>
            <input id="report-title" type="text" value={title} onChange={(e) => setTitle(e.target.value)} />
          </div>
          <div className="case-field">
            <label className="case-label" htmlFor="report-case-number">
              사건 번호 (선택)
            </label>
            <input
              id="report-case-number"
              type="text"
              value={caseNumber}
              onChange={(e) => setCaseNumber(e.target.value)}
            />
          </div>
          <div className="case-field">
            <label className="case-label" htmlFor="report-investigator">
              분석관 (선택)
            </label>
            <input
              id="report-investigator"
              type="text"
              value={investigator}
              onChange={(e) => setInvestigator(e.target.value)}
            />
          </div>
        </>
      ) : null}
      {exportMutation.error && (
        <ErrorText>
          {exportMutation.error instanceof Error ? exportMutation.error.message : "내보내지 못했습니다."}
        </ErrorText>
      )}
    </Modal>
  );
}
