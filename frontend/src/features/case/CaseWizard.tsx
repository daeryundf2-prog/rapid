/**
 * 케이스 만들기 (AXIOM adoption E1, plan §3.1): a 3-step modal — 사건 정보 / 증거 추가 N (해시 검증 토글)
 * / 처리 옵션 (the quick-run dialog's option fields + a summary built from the exact request body).
 * 다음 on the evidence step pre-checks every path (`POST /api/cases/evidence-check`: path policy, kind,
 * runnable). 실행 creates the case, adds each evidence item and starts one run per RUNNABLE item
 * (register-only evidence, e.g. a .zip export, is saved and skipped with a notice), then opens the
 * first run's 접수 stage. A failure keeps what was already saved (the case, saved evidence) and
 * retrying continues from the failed call; an evidence 409 adopts the already-saved row.
 */

import { useQueryClient } from "@tanstack/react-query";
import { type KeyboardEvent, useEffect, useId, useRef, useState } from "react";
import {
  addEvidence,
  type CaseEvidence,
  type CaseRunBody,
  checkEvidence,
  createCase,
  createCaseRun,
  koCompare,
  listEvidence,
} from "../../api/cases";
import { ApiError } from "../../api/client";
import { navigate } from "../tree/adapter";
import { AiRunOptionsField } from "./AiRunOptionsField";
import { ErrorText } from "./ErrorText";
import { EvidenceFields } from "./EvidenceFields";
import { Modal } from "./Modal";
import { ReasonButton } from "./ReasonButton";
import { RunOptionsFields } from "./RunOptionsFields";
import { RunPlanGroupsField } from "./RunPlanGroupsField";
import { buildRunBody, DEFAULT_RUN_FORM, firstRunFormError, type RunForm, validateRunForm } from "./runForm";
import { summarizeRunRequest } from "./runSummary";
import {
  CASE_TYPE_SUGGESTIONS,
  type CaseInfoForm,
  caseBody,
  type DraftCheck,
  draftCheckKey,
  EMPTY_CASE_INFO,
  EVIDENCE_TYPE_LABEL,
  type EvidenceDraft,
  evidenceBody,
  evidenceListReason,
  firstError,
  newEvidenceDraft,
  outputDirReason,
  runnableDrafts,
  samePathText,
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

/** Pre-check one draft; a failed check (older server, network) leaves the gate to the server. */
async function checkDraft(draft: EvidenceDraft): Promise<DraftCheck> {
  const key = draftCheckKey(draft);
  try {
    const result = await checkEvidence(draft.path.trim(), draft.sourceType);
    return {
      for: key,
      ok: result.ok,
      problem: result.problem,
      runnable: result.runnable,
      reason: result.run_blocked_reason,
    };
  } catch {
    return { for: key, ok: true, problem: "", runnable: true, reason: "", unverified: true };
  }
}

/**
 * The saved row a 409 on 증거 추가 refers to (a retry after the first response was lost): the row
 * with this path (the server keeps one row per path, so its number is the one citations must use),
 * else null. A row with the same number but another path is a real conflict, not adopted.
 */
export function adoptableEvidence(rows: CaseEvidence[], draft: EvidenceDraft): CaseEvidence | null {
  return rows.find((row) => samePathText(row.path, draft.path)) ?? null;
}

/** 사건 유형 choices (C-L2): the listed types, then 기타 with its own text field. */
const CASE_TYPE_CHOICES = CASE_TYPE_SUGGESTIONS.filter((type) => type !== "기타");
const CASE_TYPE_OTHER = "__other__";

const INPUT_TYPES_WITHOUT_ENTER = new Set(["checkbox", "radio", "button", "submit", "reset", "file"]);

interface Progress {
  caseId: string | null;
  caseNumber: string;
  evidence: Record<string, string>;
  runs: Record<string, string>;
}

const CASE_FIELDS: Array<{ key: keyof CaseInfoForm; label: string; max: number; hint?: string }> = [
  { key: "name", label: "사건명", max: 200 },
  { key: "examiner", label: "분석관", max: 200, hint: "메모·태그의 기본 작성자" },
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
  const [checking, setChecking] = useState(false);
  const [checks, setChecks] = useState<Record<string, DraftCheck>>({});
  const [error, setError] = useState("");
  // 사건 유형 "기타": the free-text field is shown (also for a typed value that is not a listed type).
  const [caseTypeOther, setCaseTypeOther] = useState(false);
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
  const sortedDrafts = [...drafts].sort((a, b) => koCompare(a.evidenceNumber, b.evidenceNumber));
  // Pre-check results still valid for the draft as it is now (editing type/path makes them stale).
  const freshChecks: Record<string, DraftCheck> = {};
  for (const draft of drafts) {
    const check = checks[draft.key];
    if (check && check.for === draftCheckKey(draft)) freshChecks[draft.key] = check;
  }
  const checkProblem = drafts
    .map((draft) => {
      const check = freshChecks[draft.key];
      return check && !check.ok ? `증거 ${draft.evidenceNumber.trim()}: ${check.problem}` : undefined;
    })
    .find(Boolean);
  const uncheckedReason = drafts.some((draft) => !freshChecks[draft.key])
    ? "증거 경로를 확인하지 않았습니다. 이전 단계에서 다음을 누르세요"
    : undefined;
  const toRun = runnableDrafts(sortedDrafts, freshChecks);
  const registerOnly = sortedDrafts.filter((draft) => freshChecks[draft.key]?.runnable === false);
  const submitReason = busy
    ? "처리 중입니다"
    : runIsActive && toRun.length > 0
      ? "실행 중 런이 있습니다"
      : (infoReason ??
        evidenceReason ??
        uncheckedReason ??
        checkProblem ??
        runReason ??
        outputDirReason(runForm.outputDir, toRun.length));
  const caseLocked = Boolean(progress.caseId);
  const previewBody = caseRunBody(runForm, "");
  const summary = summarizeRunRequest(previewBody as unknown as Record<string, unknown>);
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
        let saved: CaseEvidence;
        try {
          saved = await addEvidence(caseId, evidenceBody(draft));
        } catch (failure) {
          // A retry after a lost response: the row already exists — adopt it instead of failing forever.
          if (!(failure instanceof ApiError && failure.status === 409)) throw failure;
          const adopted = adoptableEvidence(await listEvidence(caseId), draft);
          if (!adopted) throw failure;
          saved = adopted;
          if (adopted.evidence_number !== draft.evidenceNumber.trim()) {
            // The server keeps one row per path; citations use that row's number.
            setDrafts((list) =>
              list.map((d) => (d.key === draft.key ? { ...d, evidenceNumber: adopted.evidence_number } : d)),
            );
          }
        }
        state.evidence[draft.key] = saved.citation_id;
        setProgress({ ...state, evidence: { ...state.evidence } });
      }
      for (const draft of toRun) {
        if (state.runs[draft.key]) continue;
        stage = `증거 ${draft.evidenceNumber.trim()} 런 시작`;
        const result = await createCaseRun(caseId, caseRunBody(runForm, state.evidence[draft.key] as string));
        state.runs[draft.key] = result.run.run_id;
        setProgress({ ...state, runs: { ...state.runs } });
      }
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
      const runIds = toRun.map((draft) => state.runs[draft.key]).filter(Boolean) as string[];
      const skipped = registerOnly.map((draft) => draft.evidenceNumber.trim()).join(", ");
      const skippedNote = registerOnly.length
        ? ` 등록만 한 증거 ${registerOnly.length}개(${skipped})는 바로 처리할 수 없는 형식이라 런을 시작하지 않았습니다.`
        : "";
      onNotice?.(
        runIds.length
          ? `케이스 ${state.caseNumber}를 만들고 런 ${runIds.length}개를 시작했습니다.${skippedNote}`
          : `케이스 ${state.caseNumber}를 만들었습니다.${skippedNote}`,
      );
      onClose();
      if (runIds[0]) navigate({ runId: runIds[0], collection: "intake" });
    } catch (failure) {
      setError(`${stage} 실패: ${messageOf(failure)}`);
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
    } finally {
      setBusy(false);
    }
  };

  const checkAll = async () => {
    setChecking(true);
    const results: Record<string, DraftCheck> = {};
    for (const draft of drafts) {
      const current = checks[draft.key];
      results[draft.key] =
        current && current.for === draftCheckKey(draft) && !current.unverified
          ? current
          : await checkDraft(draft);
    }
    setChecks(results);
    setChecking(false);
    if (Object.values(results).every((result) => result.ok)) setStep(2);
  };

  const next = () => {
    if (step === 0) {
      setInfoTouched(true);
      if (!infoReason) setStep(1);
    } else if (step === 1) {
      setEvidenceAttempted(true);
      if (!evidenceReason && !checking && !checkProblem) void checkAll();
    }
  };
  const nextReason =
    step === 0
      ? infoReason
      : step === 1
        ? (evidenceReason ?? (checking ? "증거 경로를 확인하는 중입니다" : checkProblem))
        : undefined;
  /** Enter in a one-line field = 다음 (or 실행 on the last step); IME composition Enter is ignored. */
  const onFormKeyDown = (event: KeyboardEvent<HTMLFormElement>) => {
    if (event.key !== "Enter" || event.shiftKey || event.ctrlKey || event.altKey || event.metaKey) return;
    if (event.nativeEvent.isComposing || event.keyCode === 229) return;
    const target = event.target;
    if (!(target instanceof HTMLInputElement) || INPUT_TYPES_WITHOUT_ENTER.has(target.type)) return;
    event.preventDefault();
    if (step < 2) next();
    else void submit();
  };
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
            quietReason
            onClick={next}
            data-testid="wizard-next"
          >
            다음
          </ReasonButton>
        ) : (
          <ReasonButton
            className="button primary"
            reason={submitReason}
            quietReason
            onClick={() => void submit()}
            data-testid="wizard-submit"
          >
            {busy ? "실행 중…" : toRun.length ? `실행 (런 ${toRun.length}개)` : "케이스만 만들기 (런 없음)"}
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

      {/* Enter in a one-line field moves on (다음) or starts the runs on the last step (onFormKeyDown);
          textareas, switches and buttons keep Enter. The hidden submit button keeps implicit
          submission defined for assistive tech that submits the form directly. */}
      <form
        className="wizard-form"
        noValidate
        onKeyDown={onFormKeyDown}
        onSubmit={(event) => {
          event.preventDefault();
          if (step < 2) next();
          else void submit();
        }}
      >
        <button type="submit" hidden tabIndex={-1} aria-hidden="true">
          {step < 2 ? "다음" : "실행"}
        </button>
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
            <div className="case-field">
              <label htmlFor={`${baseId}-caseType`}>사건 유형</label>
              <select
                id={`${baseId}-caseType`}
                value={
                  caseTypeOther || (info.caseType !== "" && !CASE_TYPE_CHOICES.includes(info.caseType))
                    ? CASE_TYPE_OTHER
                    : info.caseType
                }
                disabled={caseLocked}
                onChange={(e) => {
                  const value = e.target.value;
                  setCaseTypeOther(value === CASE_TYPE_OTHER);
                  setField("caseType", value === CASE_TYPE_OTHER ? "" : value);
                }}
              >
                <option value="">선택 안 함</option>
                {CASE_TYPE_CHOICES.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
                <option value={CASE_TYPE_OTHER}>기타 (직접 입력)</option>
              </select>
              {caseTypeOther || (info.caseType !== "" && !CASE_TYPE_CHOICES.includes(info.caseType)) ? (
                <input
                  id={`${baseId}-caseType-other`}
                  type="text"
                  aria-label="사건 유형 (기타, 직접 입력)"
                  value={info.caseType}
                  maxLength={100}
                  disabled={caseLocked}
                  placeholder="사건 유형을 입력하세요"
                  onChange={(e) => setField("caseType", e.target.value)}
                />
              ) : null}
            </div>
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
                  "지정하면 런 출력이 이 폴더 아래 증거 번호별로 만들어집니다. 비우면 폴더 증거는 그 폴더 안에, 파일 증거는 파일 옆에 만듭니다 (그 위치에 쓸 수 있어야 합니다)."}
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
              const check = freshChecks[draft.key];
              return (
                <fieldset key={draft.key} className="case-evidence" data-testid="wizard-evidence">
                  <legend>증거 {label}</legend>
                  {saved ? <p className="case-reason">케이스에 저장됨 · {saved}</p> : null}
                  {check && !check.ok ? (
                    <p className="case-error" data-testid="wizard-evidence-problem">
                      경로 확인: {check.problem}
                    </p>
                  ) : null}
                  {check?.ok && !check.runnable ? (
                    <p className="case-reason" data-testid="wizard-register-only">
                      등록만: {check.reason}
                    </p>
                  ) : null}
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
            {checking ? <p aria-busy="true">증거 경로를 확인하는 중…</p> : null}
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
            <RunPlanGroupsField
              form={runForm}
              onChange={(skipGroups) => setRun("skipGroups", skipGroups)}
              idPrefix={`${baseId}-run`}
            />
            <AiRunOptionsField
              form={runForm}
              onChange={(patch) => {
                if (patch.aiBodies !== undefined) setRun("aiBodies", patch.aiBodies);
                if (patch.aiHashDbs !== undefined) setRun("aiHashDbs", patch.aiHashDbs);
              }}
              idPrefix={`${baseId}-run`}
            />
            {outputDirReason(runForm.outputDir, toRun.length) ? (
              <p className="case-error" data-testid="wizard-output-dir-problem">
                {outputDirReason(runForm.outputDir, toRun.length)}
              </p>
            ) : null}
            {registerOnly.length ? (
              <p className="case-reason" data-testid="wizard-skipped">
                등록만 하는 증거 {registerOnly.length}개 (
                {registerOnly.map((draft) => draft.evidenceNumber.trim()).join(", ")}) — 케이스에 저장하지만
                런은 시작하지 않습니다.
              </p>
            ) : null}
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
                  <dt>분석관</dt>
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
                  <th scope="col">런</th>
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
                    <td>
                      {freshChecks[draft.key]?.runnable === false
                        ? `등록만 — ${freshChecks[draft.key]?.reason ?? ""}`
                        : freshChecks[draft.key]?.unverified
                          ? "시작 (서버에서 확인)"
                          : "시작"}
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
