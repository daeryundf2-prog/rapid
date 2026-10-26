import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useId, useState } from "react";
import { getReviewCounts } from "../../api/caseDb";
import { caseLinkOf } from "./caseLink";
import { ErrorText } from "./ErrorText";
import {
  EXPORT_ACTIONS,
  type ExportKind,
  exportDisabledReason,
  exportWrites,
  performExport,
  type ReportFormat,
  writtenDetail,
} from "./exports";
import { Modal } from "./Modal";
import { ReasonButton } from "./ReasonButton";
import { notifyWritten, runOutputDir } from "./WriteConfirm";

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
  initialKind = "case-report",
}: {
  runId: string | null;
  runIsActive: boolean;
  onClose: () => void;
  /** The kind chosen when the dialog opens (보고 panel / palette `export.*`). */
  initialKind?: ExportKind;
}) {
  const [kind, setKind] = useState<ExportKind>(initialKind);
  // Where the files go (r7 L4): the run folder, known before anything is written.
  const [folder, setFolder] = useState<string | null>(null);
  useEffect(() => {
    if (!runId) return;
    let alive = true;
    void runOutputDir(runId).then((dir) => {
      if (alive) setFolder(dir);
    });
    return () => {
      alive = false;
    };
  }, [runId]);
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
    onSuccess: (result, chosen) => {
      const label = EXPORT_ACTIONS.find((action) => action.kind === chosen)?.label ?? "내보내기";
      const written = result.written ?? [];
      notifyWritten(
        written.length > 1
          ? `${label}: ${written.length}개 파일을 썼습니다 (${result.fileName}은(는) 다운로드 폴더에도 저장).`
          : `${label}: ${result.fileName}을(를) 저장했습니다.`,
        written.length > 1 ? writtenDetail(written) : result.path,
        result.open ? { label: "열기", run: () => void result.open?.() } : undefined,
      );
      onClose();
    },
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
      <section className="case-field" aria-labelledby={`${groupId}-where`} data-testid="export-writes">
        <h3 id={`${groupId}-where`} className="case-label">
          쓰는 위치
        </h3>
        <ul className="write-confirm-list">
          {exportWrites(kind, folder, format).map((item) => (
            <li key={item.where}>
              {item.what}
              <div className="write-confirm-where">{item.where}</div>
            </li>
          ))}
        </ul>
        <p className="case-reason">
          내보내기를 누르기 전에는 아무것도 쓰지 않습니다. 원본 증거는 바꾸지 않습니다.
        </p>
      </section>
      {exportMutation.error && (
        <ErrorText>
          {exportMutation.error instanceof Error ? exportMutation.error.message : "내보내지 못했습니다."}
        </ErrorText>
      )}
    </Modal>
  );
}
