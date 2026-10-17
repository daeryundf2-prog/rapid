/**
 * Case intake dialogs (AXIOM adoption E1): 케이스에 연결 · 사건 정보 편집 · 증거 추가 · 런 추가 ·
 * 처리 문제 전체 보기. Each one is a Modal (labelled dialog, Esc closes, focus returns) opened via
 * the case dialog store; results are announced through the shell's polite region (setNotice).
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import {
  addEvidence,
  type CaseDetail,
  createCaseRun,
  getCase,
  getRunProblems,
  koCompare,
  linkCaseRun,
  listCases,
  patchCase,
} from "../../api/cases";
import { ApiError } from "../../api/client";
import { navigate } from "../tree/adapter";
import { caseRunBody, caseRunFormReason } from "./CaseWizard";
import { snapshotQueryKey } from "./caseLink";
import { ErrorText } from "./ErrorText";
import { EvidenceFields } from "./EvidenceFields";
import { Modal } from "./Modal";
import { ReasonButton } from "./ReasonButton";
import { RunOptionsFields } from "./RunOptionsFields";
import { DEFAULT_RUN_FORM, type RunForm, validateRunForm } from "./runForm";
import { summarizeRunRequest } from "./runSummary";
import {
  CASE_TYPE_SUGGESTIONS,
  type CaseInfoForm,
  EVIDENCE_TYPE_LABEL,
  type EvidenceDraft,
  evidenceBody,
  firstError,
  newEvidenceDraft,
  validateCaseInfo,
  validateEvidenceDraft,
} from "./wizardModel";

function messageOf(error: unknown): string {
  return error instanceof ApiError || error instanceof Error ? error.message : "알 수 없는 오류";
}

const caseQueryKey = (caseId: string) => ["case", caseId] as const;

function useCaseQuery(caseId: string | undefined) {
  return useQuery({
    queryKey: caseQueryKey(caseId ?? ""),
    queryFn: () => getCase(caseId as string),
    enabled: Boolean(caseId),
    retry: false,
  });
}

function invalidateCase(queryClient: ReturnType<typeof useQueryClient>, caseId: string, runId?: string) {
  void queryClient.invalidateQueries({ queryKey: ["cases"] });
  void queryClient.invalidateQueries({ queryKey: caseQueryKey(caseId) });
  if (runId) void queryClient.invalidateQueries({ queryKey: snapshotQueryKey(runId) });
  void queryClient.invalidateQueries({ queryKey: ["processing-snapshot"] });
}

// --- 케이스에 연결 -------------------------------------------------------------

export function LinkCaseDialog({
  runId,
  onClose,
  onNotice,
}: {
  runId: string;
  onClose: () => void;
  onNotice?: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const id = useId();
  const cases = useQuery({ queryKey: ["cases"], queryFn: listCases, retry: false });
  const [caseId, setCaseId] = useState("");
  const [evidenceId, setEvidenceId] = useState("");
  const [evidenceNumber, setEvidenceNumber] = useState("");
  const sorted = [...(cases.data ?? [])].sort((a, b) => koCompare(a.case_number, b.case_number));
  const chosen = sorted.find((item) => item.case_id === caseId);
  const evidence = [...(chosen?.evidence ?? [])].sort((a, b) =>
    koCompare(a.evidence_number, b.evidence_number),
  );
  const reason = !caseId
    ? "연결할 케이스를 고르세요"
    : !evidenceId && !evidenceNumber.trim()
      ? "기존 증거를 고르거나 새 증거 번호를 입력하세요"
      : undefined;
  const link = useMutation({
    mutationFn: () =>
      linkCaseRun(caseId, {
        run_id: runId,
        evidence_citation_id: evidenceId || null,
        evidence_number: evidenceId ? null : evidenceNumber.trim(),
      }),
    onSuccess: () => {
      invalidateCase(queryClient, caseId, runId);
      onNotice?.(`런을 케이스 ${chosen?.case_number ?? ""}에 연결했습니다.`);
      onClose();
    },
  });
  return (
    <Modal
      title="케이스에 연결"
      onClose={onClose}
      footer={
        <div className="case-actions">
          <button type="button" className="button" onClick={onClose}>
            취소
          </button>
          <ReasonButton className="button primary" reason={reason} onClick={() => link.mutate()}>
            연결
          </ReasonButton>
        </div>
      }
    >
      <p className="case-reason">이 런의 처리 옵션을 케이스에 스냅숏으로 남기고 증거 번호를 붙입니다.</p>
      {cases.isPending ? <p aria-busy="true">케이스 목록을 불러오는 중…</p> : null}
      {cases.isError ? <ErrorText>케이스 목록을 불러오지 못했습니다.</ErrorText> : null}
      {cases.data && sorted.length === 0 ? (
        <p>아직 케이스가 없습니다. 먼저 "케이스 만들기"로 케이스를 만드세요.</p>
      ) : null}
      {sorted.length ? (
        <>
          <div className="case-field">
            <label htmlFor={`${id}-case`}>케이스</label>
            <select
              id={`${id}-case`}
              value={caseId}
              onChange={(e) => {
                setCaseId(e.target.value);
                setEvidenceId("");
              }}
            >
              <option value="">선택</option>
              {sorted.map((item) => (
                <option key={item.case_id} value={item.case_id}>
                  {item.case_number} · {item.name}
                </option>
              ))}
            </select>
          </div>
          <div className="case-field">
            <label htmlFor={`${id}-evidence`}>증거</label>
            <select
              id={`${id}-evidence`}
              value={evidenceId}
              disabled={!caseId}
              onChange={(e) => setEvidenceId(e.target.value)}
            >
              <option value="">새 증거로 추가 (런의 증거 경로)</option>
              {evidence.map((item) => (
                <option key={item.citation_id} value={item.citation_id}>
                  {item.evidence_number} · {item.display_name}
                </option>
              ))}
            </select>
          </div>
          {!evidenceId ? (
            <div className="case-field">
              <label htmlFor={`${id}-number`}>새 증거 번호</label>
              <input
                id={`${id}-number`}
                type="text"
                maxLength={50}
                value={evidenceNumber}
                onChange={(e) => setEvidenceNumber(e.target.value)}
              />
            </div>
          ) : null}
        </>
      ) : null}
      {link.error ? <ErrorText>{messageOf(link.error)}</ErrorText> : null}
    </Modal>
  );
}

// --- 사건 정보 편집 ------------------------------------------------------------

function infoFromCase(detail: CaseDetail): CaseInfoForm {
  return {
    caseNumber: detail.case_number,
    name: detail.name,
    caseType: detail.case_type,
    examiner: detail.examiner,
    requester: detail.requester,
    organization: detail.organization,
    description: detail.description,
    caseRoot: detail.case_root,
  };
}

const EDIT_FIELDS: Array<{ key: keyof CaseInfoForm; label: string; max: number }> = [
  { key: "caseNumber", label: "사건 번호", max: 100 },
  { key: "name", label: "사건명", max: 200 },
  { key: "caseType", label: "사건 유형", max: 100 },
  { key: "examiner", label: "검사관", max: 200 },
  { key: "requester", label: "의뢰처", max: 200 },
  { key: "organization", label: "소속", max: 200 },
];

export function CaseEditDialog({
  caseId,
  onClose,
  onNotice,
}: {
  caseId: string;
  onClose: () => void;
  onNotice?: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const id = useId();
  const detail = useCaseQuery(caseId);
  const [form, setForm] = useState<CaseInfoForm | null>(null);
  const current = form ?? (detail.data ? infoFromCase(detail.data) : null);
  const errors = current ? validateCaseInfo({ ...current, caseRoot: "" }) : {};
  const reason = !current ? "사건 정보를 불러오는 중입니다" : firstError(errors);
  const save = useMutation({
    mutationFn: () => {
      const value = current as CaseInfoForm;
      return patchCase(caseId, {
        case_number: value.caseNumber.trim(),
        name: value.name.trim(),
        case_type: value.caseType.trim(),
        examiner: value.examiner.trim(),
        requester: value.requester.trim(),
        organization: value.organization.trim(),
        description: value.description.trim(),
      });
    },
    onSuccess: (saved) => {
      queryClient.setQueryData(caseQueryKey(caseId), saved);
      invalidateCase(queryClient, caseId);
      onNotice?.("사건 정보를 저장했습니다.");
      onClose();
    },
  });
  const set = (key: keyof CaseInfoForm, value: string) =>
    setForm({ ...(current as CaseInfoForm), [key]: value });
  return (
    <Modal
      title="사건 정보 편집"
      onClose={onClose}
      footer={
        <div className="case-actions">
          <button type="button" className="button" onClick={onClose}>
            취소
          </button>
          <ReasonButton className="button primary" reason={reason} onClick={() => save.mutate()}>
            저장
          </ReasonButton>
        </div>
      }
    >
      {detail.isPending ? <p aria-busy="true">사건 정보를 불러오는 중…</p> : null}
      {detail.isError ? (
        <ErrorText>사건 정보를 불러오지 못했습니다: {messageOf(detail.error)}</ErrorText>
      ) : null}
      {current ? (
        <>
          {EDIT_FIELDS.map((field) => (
            <div className="case-field" key={field.key}>
              <label htmlFor={`${id}-${field.key}`}>{field.label}</label>
              <input
                id={`${id}-${field.key}`}
                type="text"
                value={current[field.key]}
                maxLength={field.max}
                list={field.key === "caseType" ? `${id}-types` : undefined}
                aria-invalid={Boolean(errors[field.key])}
                onChange={(e) => set(field.key, e.target.value)}
              />
              {errors[field.key] ? <p className="case-error">{errors[field.key]}</p> : null}
            </div>
          ))}
          <datalist id={`${id}-types`}>
            {CASE_TYPE_SUGGESTIONS.map((type) => (
              <option key={type} value={type} />
            ))}
          </datalist>
          <div className="case-field">
            <label htmlFor={`${id}-description`}>설명</label>
            <textarea
              id={`${id}-description`}
              rows={3}
              maxLength={4000}
              value={current.description}
              onChange={(e) => set("description", e.target.value)}
            />
          </div>
          <p className="case-reason">
            인용 ID 접두({detail.data?.citation_prefix})는 이미 붙은 인용과 맞추기 위해 바뀌지 않습니다.
          </p>
        </>
      ) : null}
      {save.error ? <ErrorText>{messageOf(save.error)}</ErrorText> : null}
    </Modal>
  );
}

// --- 증거 추가 -----------------------------------------------------------------

export function AddEvidenceDialog({
  caseId,
  onClose,
  onNotice,
}: {
  caseId: string;
  onClose: () => void;
  onNotice?: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const id = useId();
  const detail = useCaseQuery(caseId);
  const existing = (detail.data?.evidence ?? []).map((item) => ({
    ...newEvidenceDraft([]),
    key: item.citation_id,
    evidenceNumber: item.evidence_number,
    path: item.path,
  }));
  const [edited, setDraft] = useState<EvidenceDraft | null>(null);
  // Until the examiner types, the next free number (E-0n) once the case's evidence is known.
  const draft = edited ?? { ...newEvidenceDraft(existing), key: "new-evidence" };
  const [attempted, setAttempted] = useState(false);
  const all = [...existing, draft];
  const errors = validateEvidenceDraft(draft, all);
  const reason = detail.isPending ? "케이스를 불러오는 중입니다" : firstError(errors);
  const save = useMutation({
    mutationFn: () => addEvidence(caseId, evidenceBody(draft)),
    onSuccess: (saved) => {
      invalidateCase(queryClient, caseId);
      onNotice?.(`증거 ${saved.evidence_number}를 추가했습니다.`);
      onClose();
    },
  });
  return (
    <Modal
      title="증거 추가"
      onClose={onClose}
      wide
      footer={
        <div className="case-actions">
          <button type="button" className="button" onClick={onClose}>
            취소
          </button>
          <ReasonButton
            className="button primary"
            reason={reason}
            onClick={() => {
              setAttempted(true);
              save.mutate();
            }}
          >
            추가
          </ReasonButton>
        </div>
      }
    >
      <EvidenceFields
        draft={draft}
        errors={errors}
        onChange={setDraft}
        idPrefix={id}
        showErrors={attempted}
      />
      {save.error ? <ErrorText>{messageOf(save.error)}</ErrorText> : null}
    </Modal>
  );
}

// --- 런 추가 -------------------------------------------------------------------

export function AddRunDialog({
  caseId,
  evidenceCitationId,
  runIsActive,
  onClose,
  onNotice,
}: {
  caseId: string;
  evidenceCitationId?: string;
  runIsActive: boolean;
  onClose: () => void;
  onNotice?: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const id = useId();
  const detail = useCaseQuery(caseId);
  const [evidenceId, setEvidenceId] = useState(evidenceCitationId ?? "");
  const [form, setForm] = useState<RunForm>(DEFAULT_RUN_FORM);
  const [advanced, setAdvanced] = useState(false);
  const evidence = [...(detail.data?.evidence ?? [])].sort((a, b) =>
    koCompare(a.evidence_number, b.evidence_number),
  );
  const chosen = evidence.find((item) => item.citation_id === evidenceId);
  const body = caseRunBody(form, evidenceId);
  const summary = summarizeRunRequest(body as unknown as Record<string, unknown>);
  const reason = runIsActive
    ? "실행 중 런이 있습니다"
    : !evidenceId
      ? "증거를 고르세요"
      : caseRunFormReason(form);
  const start = useMutation({
    mutationFn: () => createCaseRun(caseId, body),
    onSuccess: (result) => {
      invalidateCase(queryClient, caseId);
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      onNotice?.(`증거 ${chosen?.evidence_number ?? ""} 런을 시작했습니다.`);
      onClose();
      navigate({ runId: result.run.run_id, collection: "intake" });
    },
  });
  const set = <K extends keyof RunForm>(key: K, value: RunForm[K]) =>
    setForm((f) => ({ ...f, [key]: value }));
  return (
    <Modal
      title="런 추가"
      onClose={onClose}
      wide
      footer={
        <div className="case-actions">
          <button type="button" className="button" onClick={onClose}>
            취소
          </button>
          <ReasonButton className="button primary" reason={reason} onClick={() => start.mutate()}>
            실행
          </ReasonButton>
        </div>
      }
    >
      <div className="case-field">
        <label htmlFor={`${id}-evidence`}>증거</label>
        <select id={`${id}-evidence`} value={evidenceId} onChange={(e) => setEvidenceId(e.target.value)}>
          <option value="">선택</option>
          {evidence.map((item) => (
            <option key={item.citation_id} value={item.citation_id}>
              {item.evidence_number} · {EVIDENCE_TYPE_LABEL[item.source_type] ?? item.source_type} ·{" "}
              {item.display_name}
            </option>
          ))}
        </select>
      </div>
      <RunOptionsFields
        form={form}
        errors={validateRunForm({ ...form, root: "-" })}
        onChange={set}
        advanced={advanced}
        onAdvancedChange={setAdvanced}
        idPrefix={`${id}-run`}
      />
      <table className="data-table dash-table" aria-label="처리 옵션 요약">
        <tbody>
          {summary.map((row) => (
            <tr key={row.key}>
              <th scope="row">{row.label}</th>
              <td>{row.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {start.error ? <ErrorText>{messageOf(start.error)}</ErrorText> : null}
    </Modal>
  );
}

// --- 처리 문제 전체 보기 -------------------------------------------------------

export const PROBLEM_FULL_LIMIT = 5000;

export function ProblemsDialog({
  runId,
  reasonId,
  reasonLabel,
  onClose,
}: {
  runId: string;
  reasonId: string;
  reasonLabel: string;
  onClose: () => void;
}) {
  const problems = useQuery({
    queryKey: ["run-problems", runId, reasonId, "full"],
    queryFn: () => getRunProblems(runId, { reasonId, limit: PROBLEM_FULL_LIMIT }),
    retry: false,
  });
  const group = problems.data?.groups[0];
  return (
    <Modal
      title={`처리 문제 · ${reasonLabel}`}
      onClose={onClose}
      wide
      footer={
        <div className="case-actions">
          <button type="button" className="button" onClick={onClose}>
            닫기
          </button>
        </div>
      }
    >
      {problems.isPending ? <p aria-busy="true">처리 문제를 불러오는 중…</p> : null}
      {problems.isError ? <ErrorText>불러오지 못했습니다: {messageOf(problems.error)}</ErrorText> : null}
      {group ? (
        <>
          <p className="case-reason">
            {group.count.toLocaleString("ko-KR")}건
            {group.count > group.items.length
              ? ` · 처음 ${group.items.length.toLocaleString("ko-KR")}건 표시`
              : ""}
          </p>
          <table className="data-table dash-table" aria-label={`${reasonLabel} 전체 목록`}>
            <thead>
              <tr>
                <th scope="col">단계</th>
                <th scope="col">수준</th>
                <th scope="col">내용</th>
              </tr>
            </thead>
            <tbody>
              {group.items.map((item, index) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: problem items have no id; order is stable
                <tr key={index}>
                  <td className="mono">{item.step || "—"}</td>
                  <td>{LEVEL_LABEL[item.level] ?? item.level}</td>
                  <td className="break-all">{item.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : problems.data ? (
        <p>이 사유의 처리 문제가 없습니다.</p>
      ) : null}
    </Modal>
  );
}

export const LEVEL_LABEL: Record<string, string> = { error: "오류", warning: "경고", notice: "알림" };
