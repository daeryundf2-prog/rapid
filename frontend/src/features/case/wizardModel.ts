/**
 * 케이스 만들기 wizard model (AXIOM adoption E1): 사건 정보 → 증거 N → 처리 옵션. Pure validation and
 * request builders; the component (CaseWizard.tsx) only renders and posts.
 */

import type { CaseCreateBody, EvidenceCreateBody, EvidenceType } from "../../api/cases";

export interface CaseInfoForm {
  caseNumber: string;
  name: string;
  caseType: string;
  examiner: string;
  requester: string;
  organization: string;
  description: string;
  caseRoot: string;
}

export const EMPTY_CASE_INFO: CaseInfoForm = {
  caseNumber: "",
  name: "",
  caseType: "",
  examiner: "",
  requester: "",
  organization: "",
  description: "",
  caseRoot: "",
};

/** Suggestions for 사건 유형 (free text; datalist). */
export const CASE_TYPE_SUGGESTIONS = ["개인정보 유출", "기술 유출", "사기", "침해사고", "횡령·배임", "기타"];

export const EVIDENCE_TYPES: Array<{ id: EvidenceType; label: string }> = [
  { id: "e01", label: "E01 이미지" },
  { id: "folder", label: "폴더" },
  { id: "export", label: "내보내기 파일" },
  { id: "mobile", label: "모바일 추출물" },
];

export const EVIDENCE_TYPE_LABEL: Record<string, string> = Object.fromEntries(
  EVIDENCE_TYPES.map((t) => [t.id, t.label]),
);

export interface EvidenceDraft {
  key: string;
  evidenceNumber: string;
  displayName: string;
  sourceType: EvidenceType;
  path: string;
  verifyHash: boolean;
  expectedHash: string;
}

export type CaseInfoErrors = Partial<Record<keyof CaseInfoForm, string>>;
export type EvidenceErrors = Partial<Record<"evidenceNumber" | "path" | "expectedHash", string>>;

let draftSeq = 0;

export function newEvidenceDraft(existing: EvidenceDraft[]): EvidenceDraft {
  draftSeq += 1;
  const used = new Set(existing.map((d) => d.evidenceNumber.trim()));
  let index = existing.length + 1;
  let number = `E-${String(index).padStart(2, "0")}`;
  while (used.has(number)) {
    index += 1;
    number = `E-${String(index).padStart(2, "0")}`;
  }
  return {
    key: `ev-${draftSeq}`,
    evidenceNumber: number,
    displayName: "",
    sourceType: "e01",
    path: "",
    verifyHash: false,
    expectedHash: "",
  };
}

/** Client mirror of the server path policy (analyses.lexical_absolute_path); the server re-checks. */
export function pathProblem(raw: string): string | undefined {
  const text = raw.trim();
  if (!text) return undefined;
  if (text.startsWith("~")) return "홈 디렉터리(~) 표기는 쓸 수 없습니다.";
  if (/^[\\/]{2}/.test(text)) return "UNC·장치 경로(\\\\server, \\\\?\\)는 쓸 수 없습니다.";
  if (/^[A-Za-z]:[\\/]/.test(text) || text.startsWith("/")) return undefined;
  return "드라이브 문자를 포함한 절대 경로여야 합니다.";
}

export function validateCaseInfo(form: CaseInfoForm): CaseInfoErrors {
  const errors: CaseInfoErrors = {};
  if (!form.caseNumber.trim()) errors.caseNumber = "사건 번호를 입력하세요.";
  else if (form.caseNumber.trim().length > 100) errors.caseNumber = "사건 번호는 100자 이하여야 합니다.";
  const root = pathProblem(form.caseRoot);
  if (root) errors.caseRoot = `케이스 폴더: ${root}`;
  return errors;
}

const HASH = /^[0-9a-fA-F]+$/;

export function validateEvidenceDraft(draft: EvidenceDraft, all: EvidenceDraft[]): EvidenceErrors {
  const errors: EvidenceErrors = {};
  const number = draft.evidenceNumber.trim();
  if (!number) errors.evidenceNumber = "증거 번호를 입력하세요.";
  else if (all.some((other) => other.key !== draft.key && other.evidenceNumber.trim() === number)) {
    errors.evidenceNumber = "증거 번호가 중복됩니다.";
  }
  const path = draft.path.trim();
  if (!path) errors.path = "증거 경로를 입력하세요.";
  else {
    const problem = pathProblem(path);
    if (problem) errors.path = problem;
    else if (draft.sourceType === "e01" && !/\.(e01|ex01)$/i.test(path)) {
      errors.path = "E01 증거는 .E01/.Ex01 파일이어야 합니다.";
    } else if (all.some((other) => other.key !== draft.key && other.path.trim() === path)) {
      errors.path = "같은 경로의 증거가 이미 있습니다.";
    }
  }
  const expected = draft.expectedHash.trim();
  if (draft.verifyHash && expected && (!HASH.test(expected) || ![32, 40, 64].includes(expected.length))) {
    errors.expectedHash = "기대 해시는 MD5(32자)·SHA-1(40자)·SHA-256(64자) 16진수여야 합니다.";
  }
  return errors;
}

export function firstError(errors: Record<string, string | undefined>): string | undefined {
  return Object.values(errors).find(Boolean);
}

/** Reason the 증거 step cannot continue (undefined = ok). */
export function evidenceListReason(drafts: EvidenceDraft[]): string | undefined {
  if (drafts.length === 0) return "증거를 하나 이상 추가하세요.";
  for (const [index, draft] of drafts.entries()) {
    const message = firstError(validateEvidenceDraft(draft, drafts));
    if (message) return `증거 ${draft.evidenceNumber.trim() || index + 1}: ${message}`;
  }
  return undefined;
}

export function caseBody(form: CaseInfoForm): CaseCreateBody {
  return {
    case_number: form.caseNumber.trim(),
    name: form.name.trim(),
    case_type: form.caseType.trim(),
    examiner: form.examiner.trim(),
    requester: form.requester.trim(),
    organization: form.organization.trim(),
    description: form.description.trim(),
    case_root: form.caseRoot.trim(),
  };
}

export function evidenceBody(draft: EvidenceDraft): EvidenceCreateBody {
  return {
    evidence_number: draft.evidenceNumber.trim(),
    display_name: draft.displayName.trim(),
    source_type: draft.sourceType,
    path: draft.path.trim(),
    verify_hash: draft.verifyHash,
    expected_hash: draft.verifyHash ? draft.expectedHash.trim() : "",
  };
}

export const WIZARD_STEPS = ["사건 정보", "증거 추가", "처리 옵션"] as const;
