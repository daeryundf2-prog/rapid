/**
 * Case intake API (AXIOM adoption E1, rapidtriage/api/app/routes_cases.py):
 * cases → evidence → runs, processing snapshots, problems by reason, case notes.
 */

import { api } from "./client";
import type { RunCreateBody, RunJob } from "./runs";

const enc = encodeURIComponent;
const caseUrl = (caseId: string) => `/api/cases/${enc(caseId)}`;

export type EvidenceType = "e01" | "folder" | "export" | "mobile";

export interface CaseRunBrief {
  run_id: string;
  exists: boolean;
  status: string;
  created_at: string | null;
  completed_at: string | null;
  mode: string | null;
  root: string | null;
  captured_at?: string;
}

export interface CaseEvidence {
  citation_id: string;
  case_id: string;
  evidence_number: string;
  display_name: string;
  source_type: EvidenceType | string;
  path: string;
  size_bytes: number | null;
  hash_verify: boolean;
  hash_expected: string;
  hash_status: string;
  hash_status_label: string;
  hash_message: string;
  hashes: Partial<Record<"md5" | "sha1" | "sha256", string>>;
  added_at: string | null;
  runs: CaseRunBrief[];
  /** The run gate: folders always run; a file only when an adapter reads it directly (else 등록만). */
  runnable?: boolean;
  run_blocked_reason?: string;
}

export interface CaseInfo {
  case_id: string;
  case_number: string;
  name: string;
  case_type: string;
  examiner: string;
  requester: string;
  organization: string;
  description: string;
  case_root: string;
  citation_prefix: string;
  status: string;
  created_at: string | null;
  updated_at: string | null;
}

export interface CaseDetail extends CaseInfo {
  evidence_count: number;
  run_count: number;
  note_count: number;
  evidence: CaseEvidence[];
}

export interface CaseCreateBody {
  case_number: string;
  name?: string;
  case_type?: string;
  examiner?: string;
  requester?: string;
  organization?: string;
  description?: string;
  case_root?: string;
}

export type CasePatchBody = Partial<Omit<CaseCreateBody, "case_root">> & { status?: "open" | "closed" };

export interface EvidenceCreateBody {
  evidence_number: string;
  display_name?: string;
  source_type: EvidenceType;
  path: string;
  verify_hash: boolean;
  expected_hash?: string;
}

export interface ProcessingSnapshotBody {
  version?: string;
  captured_at?: string;
  origin?: "case-run" | "linked-run" | "run-request" | string;
  case?: Partial<CaseInfo> | null;
  evidence?: Partial<CaseEvidence> | null;
  request?: Partial<RunCreateBody> & Record<string, unknown>;
  profile?: {
    mode?: string;
    description?: string;
    keywords?: string[];
    artifacts_kinds?: string[];
    file_scan_categories?: string[];
  };
  safety?: Record<string, unknown>;
  resource_caps?: Record<string, unknown>;
  file?: string | null;
}

export interface ProcessingSnapshot {
  source: "case-db" | "run-request";
  run_id: string;
  case_id: string | null;
  evidence_citation_id: string | null;
  captured_at: string | null;
  snapshot: ProcessingSnapshotBody;
  case: CaseInfo | null;
  evidence: CaseEvidence | null;
}

export interface ProblemItem {
  source: string;
  step: string;
  level: string;
  message: string;
}

export interface ProblemGroup {
  reason_id: string;
  label_ko: string;
  level: string;
  count: number;
  steps: string[];
  items: ProblemItem[];
}

export interface RunProblems {
  run_id: string;
  total: number;
  by_level: Record<string, number>;
  limit: number;
  groups: ProblemGroup[];
}

export interface CaseNote {
  id: number;
  case_id: string;
  author: string;
  text: string;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
  deleted_by: string;
}

export interface CaseNoteHistory {
  id: number;
  note_id: number;
  action: "created" | "deleted" | string;
  actor: string;
  at: string;
  text: string;
}

export interface CaseNotes {
  notes: CaseNote[];
  count: number;
  deleted_count: number;
  history: CaseNoteHistory[];
}

/** Arrays always present (older servers / partial payloads). */
function normalizeCase(raw: CaseDetail): CaseDetail {
  return {
    ...raw,
    evidence: (Array.isArray(raw.evidence) ? raw.evidence : []).map((item) => ({
      ...item,
      runs: Array.isArray(item.runs) ? item.runs : [],
      hashes: item.hashes ?? {},
    })),
  };
}

export async function listCases(): Promise<CaseDetail[]> {
  const raw = await api<{ cases?: CaseDetail[] } | null>("/api/cases");
  return Array.isArray(raw?.cases) ? raw.cases.map(normalizeCase) : [];
}

export async function getCase(caseId: string): Promise<CaseDetail> {
  return normalizeCase((await api<{ case: CaseDetail }>(caseUrl(caseId))).case);
}

export async function createCase(body: CaseCreateBody): Promise<CaseDetail> {
  return normalizeCase(
    (await api<{ case: CaseDetail }>("/api/cases", { method: "POST", body: JSON.stringify(body) })).case,
  );
}

export async function patchCase(caseId: string, body: CasePatchBody): Promise<CaseDetail> {
  return normalizeCase(
    (await api<{ case: CaseDetail }>(caseUrl(caseId), { method: "PATCH", body: JSON.stringify(body) })).case,
  );
}

export async function addEvidence(caseId: string, body: EvidenceCreateBody): Promise<CaseEvidence> {
  return (
    await api<{ evidence: CaseEvidence }>(`${caseUrl(caseId)}/evidence`, {
      method: "POST",
      body: JSON.stringify(body),
    })
  ).evidence;
}

export async function listEvidence(caseId: string): Promise<CaseEvidence[]> {
  return (await api<{ evidence: CaseEvidence[] }>(`${caseUrl(caseId)}/evidence`)).evidence ?? [];
}

/** `POST /api/cases/evidence-check`: path policy, kind and whether a run can start (nothing is saved). */
export interface EvidenceCheck {
  ok: boolean;
  problem: string;
  runnable: boolean;
  run_blocked_reason: string;
}

export async function checkEvidence(path: string, sourceType: EvidenceType): Promise<EvidenceCheck> {
  const raw = await api<Partial<EvidenceCheck>>("/api/cases/evidence-check", {
    method: "POST",
    body: JSON.stringify({ path, source_type: sourceType }),
  });
  return {
    ok: raw?.ok !== false,
    problem: raw?.problem ?? "",
    runnable: raw?.runnable !== false,
    run_blocked_reason: raw?.run_blocked_reason ?? "",
  };
}

/** `POST /api/cases/{id}/evidence/{eid}/hash`: hash a file evidence item (again). */
export async function rehashEvidence(caseId: string, citationId: string, actor = ""): Promise<CaseEvidence> {
  const query = actor ? `?actor=${enc(actor)}` : "";
  return (
    await api<{ evidence: CaseEvidence }>(`${caseUrl(caseId)}/evidence/${enc(citationId)}/hash${query}`, {
      method: "POST",
    })
  ).evidence;
}

/** `POST /api/cases/{id}/runs` = RunCreateRequest + evidence_citation_id (root = the evidence path). */
export type CaseRunBody = Omit<RunCreateBody, "root"> & { evidence_citation_id: string };

export interface CaseRunResult {
  run: RunJob;
  snapshot: { run_id: string; snapshot: ProcessingSnapshotBody };
  snapshot_file: string | null;
  snapshot_file_error: string | null;
}

export function createCaseRun(caseId: string, body: CaseRunBody): Promise<CaseRunResult> {
  return api<CaseRunResult>(`${caseUrl(caseId)}/runs`, { method: "POST", body: JSON.stringify(body) });
}

export interface CaseRunLinkBody {
  run_id: string;
  evidence_citation_id?: string | null;
  evidence_number?: string | null;
  /** Link to evidence whose path differs from the run root; the reason goes to the audit. */
  force?: boolean;
  force_reason?: string;
}

export function linkCaseRun(caseId: string, body: CaseRunLinkBody): Promise<unknown> {
  return api(`${caseUrl(caseId)}/runs/link`, { method: "POST", body: JSON.stringify(body) });
}

export async function getProcessingSnapshot(runId: string): Promise<ProcessingSnapshot> {
  const raw = await api<Partial<ProcessingSnapshot> | null>(`/api/runs/${enc(runId)}/processing-snapshot`);
  // Older servers / partial payloads: never let a card read through `undefined`.
  return {
    source: raw?.source === "case-db" ? "case-db" : "run-request",
    run_id: raw?.run_id ?? runId,
    case_id: raw?.case_id ?? null,
    evidence_citation_id: raw?.evidence_citation_id ?? null,
    captured_at: raw?.captured_at ?? null,
    snapshot: raw?.snapshot && typeof raw.snapshot === "object" ? raw.snapshot : {},
    case: raw?.case ?? null,
    evidence: raw?.evidence ?? null,
  };
}

export async function getRunProblems(
  runId: string,
  options: { reasonId?: string; limit?: number } = {},
): Promise<RunProblems> {
  const params = new URLSearchParams();
  if (options.reasonId) params.set("reason_id", options.reasonId);
  if (options.limit) params.set("limit", String(options.limit));
  const query = params.toString();
  const raw = await api<Partial<RunProblems>>(`/api/runs/${enc(runId)}/problems${query ? `?${query}` : ""}`);
  const groups = Array.isArray(raw?.groups)
    ? raw.groups.map((group) => ({ ...group, steps: group.steps ?? [], items: group.items ?? [] }))
    : [];
  return {
    run_id: raw?.run_id ?? runId,
    total: raw?.total ?? groups.reduce((sum, group) => sum + (group.count ?? 0), 0),
    by_level: raw?.by_level ?? {},
    limit: raw?.limit ?? options.limit ?? 20,
    groups,
  };
}

export async function listCaseNotes(caseId: string): Promise<CaseNotes> {
  const raw = await api<Partial<CaseNotes>>(`${caseUrl(caseId)}/notes`);
  return {
    notes: raw?.notes ?? [],
    count: raw?.count ?? raw?.notes?.length ?? 0,
    deleted_count: raw?.deleted_count ?? 0,
    history: raw?.history ?? [],
  };
}

export async function addCaseNote(
  caseId: string,
  body: { text: string; author?: string },
): Promise<CaseNote> {
  return (
    await api<{ note: CaseNote }>(`${caseUrl(caseId)}/notes`, { method: "POST", body: JSON.stringify(body) })
  ).note;
}

export async function deleteCaseNote(caseId: string, noteId: number, actor = ""): Promise<CaseNote> {
  const query = actor ? `?actor=${enc(actor)}` : "";
  return (await api<{ note: CaseNote }>(`${caseUrl(caseId)}/notes/${noteId}${query}`, { method: "DELETE" }))
    .note;
}

/** Korean-aware natural order (사건 번호, 증거 번호, 표시 이름). */
export const koCompare = (a: string, b: string): number =>
  a.localeCompare(b, "ko", { numeric: true, sensitivity: "base" });
