/**
 * 케이스 만들기 (AXIOM adoption E1, plan §3.1): a 3-step modal — 사건 정보 / 증거 추가 N (해시 검증 토글)
 * / 처리 옵션 (the quick-run dialog's option fields + a summary built from the exact request body).
 * 실행 creates the case, adds each evidence item and starts one run per item, then opens the first
 * run's 접수 stage. A failure keeps what was already saved (the case, saved evidence) and retrying
 * continues from the failed call.
 */

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState } from "react";
import { addEvidence, type CaseRunBody, createCase, createCaseRun, koCompare } from "../../api/cases";
import { ApiError } from "../../api/client";
import { navigate } from "../tree/adapter";
import { ErrorText } from "./ErrorText";
import { EvidenceFields } from "./EvidenceFields";
import { Modal } from "./Modal";
import { ReasonButton } from "./ReasonButton";
import { RunOptionsFields } from "./RunOptionsFields";
import { buildRunBody, DEFAULT_RUN_FORM, firstRunFormError, type RunForm, validateRunForm } from "./runForm";
import { summarizeRunRequest } from "./runSummary";
import {
  CASE_TYPE_SUGGESTIONS,
  type CaseInfoForm,
  caseBody,
  EMPTY_CASE_INFO,
  EVIDENCE_TYPE_LABEL,
  type EvidenceDraft,
  evidenceBody,
  evidenceListReason,
  firstError,
  newEvidenceDraft,
  validateCaseInfo,
  validateEvidenceDraft,
  WIZARD_STEPS,
} from "./wizardModel";

function messageOf(error: unknown): string {
  return error instanceof ApiError || error instanceof Error ? error.message : "알 수 없는 오류";
}

/** Body of `POST /api/cases/{id}/runs` for one evidence item (root = the evidence path, server side). */
export function caseRunBody(form: RunForm, evidenceCitationId: string): CaseRunBody {
  const { root: _root, ...rest } = buildRunBody({ ...form, root: "-" });
  return { ...rest, evidence_citation_id: evidenceCitationId };
}

/** Run-form errors that matter for a case run (the evidence supplies the path). */
export function caseRunFormReason(form: RunForm): string | undefined {
  return firstRunFormError(validateRunForm({ ...form, root: "-" }));
}

interface Progress {
  caseId: string | null;
  caseNumber: string;
  evidence: Record<string, string>;
  runs: Record<string, string>;
}

const CASE_FIELDS: Array<{ key: keyof CaseInfoForm; label: string; max: number; hint?: string }> = [
  { key: "name", label: "사건명", max: 200 },
  { key: "caseType", label: "사건 유형", max: 100 },
  { key: "examiner", label: "검사관", max: 200, hint: "메모·태그의 기본 작성자" },
  { key: "requester", label: "의뢰처", max: 200 },
  { key: "organization", label: "소속", max: 200 },
];

export function CaseWizard({
  runIsActive,
  onClose,
  onNotice,
}: {
  runIsActive: boolean;
  onClose: () => void;
  onNotice?: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const baseId = useId();
  const [step, setStep] = useState(0);
  const [info, setInfo] = useState<CaseInfoForm>(EMPTY_CASE_INFO);
  const [infoTouched, setInfoTouched] = useState(false);
  const [drafts, setDrafts] = useState<EvidenceDraft[]>(() => [newEvidenceDraft([])]);
  const [evidenceAttempted, setEvidenceAttempted] = useState(false);
  const [runForm, setRunForm] = useState<RunForm>(DEFAULT_RUN_FORM);
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState<Progress>({
    caseId: null,
    caseNumber: "",
    evidence: {},
    runs: {},
  });

  const infoErrors = validateCaseInfo(info);
  const infoReason = firstError(infoErrors);
  const evidenceReason = evidenceListReason(drafts);
  const runErrors = validateRunForm({ ...runForm, root: "-" });
  const runReason = caseRunFormReason(runForm);
  const submitReason = busy
    ? "처리 중입니다"
    : runIsActive
      ? "실행 중 런이 있습니다"
      : (infoReason ?? evidenceReason ?? runReason);
  const caseLocked = Boolean(progress.caseId);
  const previewBody = caseRunBody(runForm, "");
  const summary = summarizeRunRequest(previewBody as unknown as Record<string, unknown>);
  const sortedDrafts = [...drafts].sort((a, b) => koCompare(a.evidenceNumber, b.evidenceNumber));
  const stepTitleId = `${baseId}-step-title`;
  const stepTitle = useRef<HTMLHeadingElement>(null);
  const shownStep = useRef(step);
  useEffect(() => {
    // Moving between steps puts focus on the new step's heading (the modal keeps focus inside).
    if (shownStep.current !== step) stepTitle.current?.focus();
    shownStep.current = step;
  }, [step]);

  const setRun = <K extends keyof RunForm>(key: K, value: RunForm[K]) =>
    setRunForm((f) => ({ ...f, [key]: value }));
  const setField = (key: keyof CaseInfoForm, value: string) => setInfo((f) => ({ ...f, [key]: value }));

  const submit = async () => {
    if (submitReason) return;
    setBusy(true);
    setError("");
    const state: Progress = { ...progress, evidence: { ...progress.evidence }, runs: { ...progress.runs } };
    let stage = "케이스 만들기";
    try {
      if (!state.caseId) {
        const created = await createCase(caseBody(info));
        state.caseId = created.case_id;
        state.caseNumber = created.case_number;
        setProgress({ ...state });
      }
      const caseId = state.caseId as string;
      for (const draft of drafts) {
        if (state.evidence[draft.key]) continue;
        stage = `증거 ${draft.evidenceNumber.trim()} 추가`;
        const saved = await addEvidence(caseId, evidenceBody(draft));
        state.evidence[draft.key] = saved.citation_id;
        setProgress({ ...state, evidence: { ...state.evidence } });
      }
      for (const draft of sortedDrafts) {
        if (state.runs[draft.key]) continue;
        stage = `증거 ${draft.evidenceNumber.trim()} 런 시작`;
        const result = await createCaseRun(caseId, caseRunBody(runForm, state.evidence[draft.key] as string));
        state.runs[draft.key] = result.run.run_id;
        setProgress({ ...state, runs: { ...state.runs } });
      }
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
      const runIds = sortedDrafts.map((draft) => state.runs[draft.key]).filter(Boolean) as string[];
      onNotice?.(`케이스 ${state.caseNumber}를 만들고 런 ${runIds.length}개를 시작했습니다.`);
      onClose();
      if (runIds[0]) navigate({ runId: runIds[0], collection: "intake" });
    } catch (failure) {
      setError(`${stage} 실패: ${messageOf(failure)}`);
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
    } finally {
      setBusy(false);
    }
  };

  const next = () => {
    if (step === 0) {
      setInfoTouched(true);
      if (!infoReason) setStep(1);
    } else if (step === 1) {
      setEvidenceAttempted(true);
      if (!evidenceReason) setStep(2);
    }
  };
  const nextReason = step === 0 ? infoReason : step === 1 ? evidenceReason : undefined;
  const caseNumberError = infoTouched ? infoErrors.caseNumber : undefined;

  const footer = (
    <>
      {error ? <ErrorText>{error}</ErrorText> : null}
      <div className="case-actions">
        {step > 0 ? (
          <button type="button" className="button" disabled={busy} onClick={() => setStep((s) => s - 1)}>
            이전
          </button>
        ) : null}
        <button type="button" className="button" onClick={onClose}>
          취소
        </button>
        {step < 2 ? (
          <ReasonButton
            className="button primary"
            reason={nextReason}
            onClick={next}
            data-testid="wizard-next"
          >
            다음
          </ReasonButton>
        ) : (
          <ReasonButton
            className="button primary"
            reason={submitReason}
            onClick={() => void submit()}
            data-testid="wizard-submit"
          >
            {busy ? "실행 중…" : `실행 (런 ${drafts.length}개)`}
          </ReasonButton>
        )}
      </div>
    </>
  );

  return (
    <Modal title="케이스 만들기" onClose={onClose} wide footer={footer}>
      <ol className="wizard-steps" aria-label="케이스 만들기 단계">
        {WIZARD_STEPS.map((label, index) => (
          <li
            key={label}
            className={`wizard-step${index === step ? " current" : index < step ? " done" : ""}`}
            aria-current={index === step ? "step" : undefined}
          >
            <span className="wizard-step-num" aria-hidden="true">
              {index + 1}
            </span>
            {label}
            {index < step ? <span className="visually-hidden"> (완료)</span> : null}
          </li>
        ))}
      </ol>
      <h3 id={stepTitleId} ref={stepTitle} tabIndex={-1} className="wizard-step-title">
        {step + 1}단계 · {WIZARD_STEPS[step]}
      </h3>

      {/* Enter in a field moves on (다음) or starts the runs on the last step; textareas keep Enter. */}
      <form
        className="wizard-form"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          if (step < 2) next();
          else void submit();
        }}
      >
        {step === 0 ? (
          <section aria-labelledby={stepTitleId} className="wizard-panel" data-testid="wizard-step-info">
            {caseLocked ? (
              <p className="case-reason">
                케이스가 이미 만들어졌습니다. 사건 정보는 접수 대시보드에서 편집하세요.
              </p>
            ) : null}
            <div className="case-field">
              <label htmlFor={`${baseId}-number`}>
                사건 번호 <span aria-hidden="true">*</span>
              </label>
              <input
                id={`${baseId}-number`}
                type="text"
                value={info.caseNumber}
                maxLength={100}
                required
                aria-required="true"
                aria-invalid={Boolean(caseNumberError)}
                aria-describedby={caseNumberError ? `${baseId}-number-error` : undefined}
                disabled={caseLocked}
                placeholder="예: 2026-고단-1234"
                onBlur={() => setInfoTouched(true)}
                onChange={(e) => setField("caseNumber", e.target.value)}
              />
              {caseNumberError ? (
                <p id={`${baseId}-number-error`} className="case-error">
                  {caseNumberError}
                </p>
              ) : null}
            </div>
            {CASE_FIELDS.map((field) => (
              <div className="case-field" key={field.key}>
                <label htmlFor={`${baseId}-${field.key}`}>{field.label}</label>
                <input
                  id={`${baseId}-${field.key}`}
                  type="text"
                  value={info[field.key]}
                  maxLength={field.max}
                  disabled={caseLocked}
                  list={field.key === "caseType" ? `${baseId}-types` : undefined}
                  aria-describedby={field.hint ? `${baseId}-${field.key}-hint` : undefined}
                  onChange={(e) => setField(field.key, e.target.value)}
                />
                {field.hint ? (
                  <p id={`${baseId}-${field.key}-hint`} className="case-reason">
                    {field.hint}
                  </p>
                ) : null}
              </div>
            ))}
            <datalist id={`${baseId}-types`}>
              {CASE_TYPE_SUGGESTIONS.map((type) => (
                <option key={type} value={type} />
              ))}
            </datalist>
            <div className="case-field">
              <label htmlFor={`${baseId}-description`}>설명</label>
              <textarea
                id={`${baseId}-description`}
                rows={3}
                maxLength={4000}
                value={info.description}
                disabled={caseLocked}
                onChange={(e) => setField("description", e.target.value)}
              />
            </div>
            <div className="case-field">
              <label htmlFor={`${baseId}-root`}>케이스 폴더 (선택)</label>
              <input
                id={`${baseId}-root`}
                type="text"
                value={info.caseRoot}
                maxLength={1024}
                disabled={caseLocked}
                aria-invalid={Boolean(infoErrors.caseRoot)}
                aria-describedby={`${baseId}-root-hint`}
                onChange={(e) => setField("caseRoot", e.target.value)}
              />
              <p id={`${baseId}-root-hint`} className={infoErrors.caseRoot ? "case-error" : "case-reason"}>
                {infoErrors.caseRoot ??
                  "지정하면 런 출력이 이 폴더 아래 증거 번호별로 만들어집니다. 비우면 증거 옆에 만듭니다."}
              </p>
            </div>
          </section>
        ) : null}

        {step === 1 ? (
          <section aria-labelledby={stepTitleId} className="wizard-panel" data-testid="wizard-step-evidence">
            <p className="case-reason">증거 {drafts.length}개 · 증거마다 런 1개를 시작합니다.</p>
            {drafts.map((draft, index) => {
              const saved = progress.evidence[draft.key];
              const label = draft.evidenceNumber.trim() || `${index + 1}번째`;
              return (
                <fieldset key={draft.key} className="case-evidence" data-testid="wizard-evidence">
                  <legend>증거 {label}</legend>
                  {saved ? <p className="case-reason">케이스에 저장됨 · {saved}</p> : null}
                  <EvidenceFields
                    draft={draft}
                    errors={validateEvidenceDraft(draft, drafts)}
                    idPrefix={`${baseId}-${draft.key}`}
                    locked={Boolean(saved)}
                    showErrors={evidenceAttempted}
                    onChange={(nextDraft) =>
                      setDrafts((list) => list.map((d) => (d.key === draft.key ? nextDraft : d)))
                    }
                  />
                  <ReasonButton
                    aria-label={`증거 ${label} 삭제`}
                    reason={
                      saved
                        ? "이미 케이스에 저장된 증거입니다"
                        : drafts.length === 1
                          ? "증거가 하나 이상 있어야 합니다"
                          : undefined
                    }
                    onClick={() => setDrafts((list) => list.filter((d) => d.key !== draft.key))}
                  >
                    삭제
                  </ReasonButton>
                </fieldset>
              );
            })}
            <button
              type="button"
              className="button"
              data-testid="wizard-add-evidence"
              onClick={() => setDrafts((list) => [...list, newEvidenceDraft(list)])}
            >
              증거 추가
            </button>
            {evidenceAttempted && evidenceReason ? <p className="case-error">{evidenceReason}</p> : null}
          </section>
        ) : null}

        {step === 2 ? (
          <section aria-labelledby={stepTitleId} className="wizard-panel" data-testid="wizard-step-options">
            <RunOptionsFields
              form={runForm}
              errors={runErrors}
              onChange={setRun}
              advanced={advanced}
              onAdvancedChange={setAdvanced}
              idPrefix={`${baseId}-run`}
            />
            <h4 className="wizard-summary-title">요약</h4>
            <dl className="detail-grid" aria-label="사건 정보 요약">
              <dt>사건 번호</dt>
              <dd>{info.caseNumber.trim()}</dd>
              <dt>사건명</dt>
              <dd>{info.name.trim() || info.caseNumber.trim()}</dd>
              {info.caseType.trim() ? (
                <>
                  <dt>사건 유형</dt>
                  <dd>{info.caseType.trim()}</dd>
                </>
              ) : null}
              {info.examiner.trim() ? (
                <>
                  <dt>검사관</dt>
                  <dd>{info.examiner.trim()}</dd>
                </>
              ) : null}
            </dl>
            <table className="data-table dash-table" aria-label="증거 요약">
              <thead>
                <tr>
                  <th scope="col">증거 번호</th>
                  <th scope="col">종류</th>
                  <th scope="col">경로</th>
                  <th scope="col">해시 검증</th>
                </tr>
              </thead>
              <tbody>
                {sortedDrafts.map((draft) => (
                  <tr key={draft.key}>
                    <td>{draft.evidenceNumber.trim()}</td>
                    <td>{EVIDENCE_TYPE_LABEL[draft.sourceType]}</td>
                    <td className="mono break-all">{draft.path.trim()}</td>
                    <td>
                      {draft.verifyHash ? (draft.expectedHash.trim() ? "기대값 비교" : "계산") : "안 함"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <table className="data-table dash-table" aria-label="처리 옵션 요약" data-testid="wizard-summary">
              <thead>
                <tr>
                  <th scope="col">처리 옵션</th>
                  <th scope="col">값</th>
                </tr>
              </thead>
              <tbody>
                {summary.map((row) => (
                  <tr key={row.key} data-key={row.key}>
                    <th scope="row">{row.label}</th>
                    <td>{row.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        ) : null}
      </form>
    </Modal>
  );
}
