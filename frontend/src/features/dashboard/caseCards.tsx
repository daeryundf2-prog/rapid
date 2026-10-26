/**
 * 접수 case cards (AXIOM adoption E1, plan §3.1; r7 examiner-first redesign): 사건 정보 (편집) ·
 * 증거 (증거 목록 + 증거 소스: 번호 · 종류 · 이름 · 경로 · 항목 수 · 해시 · 런 시작 / 증거 추가) ·
 * 처리 경고·제한 사항 (처리 문제 사유별 + 단계 경고 + 확인 필요 사항, 공개 사항(정보) 접힘) ·
 * 노트·메모 (검사관 한 칸 · 케이스 메모 · 요약 노트 접힘). A run without a case keeps working:
 * 사건 정보 offers "케이스에 연결", 증거 shows the run's own evidence source, 메모 explains why it is
 * empty and the problems read the run summary.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, Fragment, useId, useState } from "react";
import { announce } from "../../a11y";
import {
  addCaseNote,
  type CaseDetail,
  type CaseEvidence,
  type CaseNotes,
  deleteCaseNote,
  getCase,
  getRunProblems,
  koCompare,
  listCaseNotes,
  type ProcessingSnapshot,
  type RunProblems,
  rehashEvidence,
} from "../../api/cases";
import { type EvidenceSource, type CaseNotes as RunNotes, saveCaseNotes } from "../../api/dashboard";
import type { CanonicalCounts, RunWarning } from "../../api/runs";
import { CommandButton } from "../../commands/CommandButton";
import { StatusBadge } from "../../components/Badge";
import { ToneChip } from "../../components/ToneChip";
import { serializeRoute } from "../../router";
import { LEVEL_LABEL } from "../case/CaseDialogs";
import { useCaseDialogs } from "../case/dialogs";
import { ReasonButton } from "../case/ReasonButton";
import { summarizeRunRequest } from "../case/runSummary";
import { EVIDENCE_TYPE_LABEL } from "../case/wizardModel";
import { formatBytes, partitionLabel } from "../tree/model";
import { CardEmpty } from "./Card";
import { DisclosureList, WarningList, warningsSummary } from "./cards";
import { type DisclosureItem, isNotice, problemMessageKo, stepLabelKo } from "./disclosures";
import { evidenceItemCount, formatTime } from "./model";

const n = (value: number) => value.toLocaleString("ko-KR");
export const PROBLEM_PREVIEW = 20;

const LEVEL_TONE: Record<string, "danger" | "warn" | "info"> = {
  error: "danger",
  warning: "warn",
  notice: "info",
};
const HASH_TONE: Record<string, "ok" | "danger" | "warn" | "info" | ""> = {
  matched: "ok",
  computed: "ok",
  mismatched: "danger",
  failed: "danger",
  interrupted: "warn",
  hashing: "info",
};
/** Korean hash state of an evidence item (the server's label is the fallback). */
const HASH_LABEL: Record<string, string> = {
  "not-requested": "해시 미검증",
  hashing: "해시 계산 중",
  matched: "해시 일치",
  computed: "해시 계산됨",
  mismatched: "해시 불일치",
  failed: "해시 계산 실패",
  interrupted: "해시 계산 중단",
};

export const caseQueryKey = (caseId: string) => ["case", caseId] as const;
export const caseNotesQueryKey = (caseId: string) => ["case-notes-db", caseId] as const;

/** Case-side queries of the dashboard (the snapshot query is shared with CaseFeature's link store). */
export function useCaseIntakeData(
  runId: string,
  snapshot: ProcessingSnapshot | undefined,
  runFinished: boolean,
) {
  const caseId = snapshot?.source === "case-db" ? snapshot.case_id : null;
  const detail = useQuery({
    queryKey: caseQueryKey(caseId ?? ""),
    queryFn: () => getCase(caseId as string),
    enabled: Boolean(caseId),
    retry: false,
    // Hash verification and sibling runs change in the background.
    refetchInterval: (q) =>
      q.state.data?.evidence.some(
        (e) => e.hash_status === "hashing" || e.runs.some((r) => isActive(r.status)),
      )
        ? 3000
        : false,
  });
  const notes = useQuery({
    queryKey: caseNotesQueryKey(caseId ?? ""),
    queryFn: () => listCaseNotes(caseId as string),
    enabled: Boolean(caseId),
    retry: false,
  });
  const problems = useQuery({
    queryKey: ["run-problems", runId],
    queryFn: () => getRunProblems(runId, { limit: PROBLEM_PREVIEW }),
    enabled: runFinished,
    retry: false,
  });
  const evidenceNumber = String(
    snapshot?.evidence?.evidence_number ?? snapshot?.snapshot.evidence?.evidence_number ?? "",
  );
  return { caseId, evidenceNumber, detail, notes, problems };
}

function isActive(status: string): boolean {
  return status === "queued" || status === "running";
}

// --- 사건 정보 -------------------------------------------------------------------

export function NoCaseLink() {
  return (
    <div className="dash-empty" data-testid="no-case">
      <p className="dash-empty-title">케이스 없음</p>
      <p className="dash-empty-text">
        이 런은 케이스 없이 실행되었습니다. 케이스에 연결하면 사건 번호·증거 번호가 인용과 보고서에 붙습니다.
      </p>
      <CommandButton command="case.link" label="케이스에 연결" variant="primary" showReason />
    </div>
  );
}

export function CaseInfoCard({ detail }: { detail: CaseDetail }) {
  const rows: Array<[string, string]> = [
    ["사건 번호", detail.case_number],
    ["사건명", detail.name],
    ["사건 유형", detail.case_type],
    ["검사관", detail.examiner],
    ["의뢰처", detail.requester],
    ["소속", detail.organization],
    ["상태", detail.status === "closed" ? "종결" : "진행 중"],
    ["설명", detail.description],
    ["케이스 폴더", detail.case_root],
    ["인용 ID 접두", detail.citation_prefix],
    ["만든 시각", formatTime(detail.created_at)],
  ];
  return (
    <div className="dash-case-info" data-testid="case-info">
      <dl className="detail-grid dash-facts">
        {rows.map(([label, value]) => (
          <Fragment key={label}>
            <dt>{label}</dt>
            <dd
              className={label === "케이스 폴더" || label === "인용 ID 접두" ? "mono dash-wrap" : undefined}
            >
              {value || "—"}
            </dd>
          </Fragment>
        ))}
      </dl>
      <div className="dash-row">
        <CommandButton command="case.edit" label="편집" variant="ghost" showReason />
      </div>
    </div>
  );
}

// --- 증거 (증거 목록 + 증거 소스) ---------------------------------------------------

/** Hash statuses a file evidence item can be hashed (again) from: never asked, failed, cut by a restart. */
const REHASH_FROM = new Set(["not-requested", "failed", "interrupted"]);

/** "해시 계산" / "해시 다시 계산" for a file evidence item (POST …/evidence/{eid}/hash). */
export function EvidenceHashButton({ caseId, item }: { caseId: string; item: CaseEvidence }) {
  const client = useQueryClient();
  const rehash = useMutation({
    mutationFn: () => rehashEvidence(caseId, item.citation_id),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: caseQueryKey(caseId) });
      announce(`증거 ${item.evidence_number} 해시 계산을 시작했습니다`);
    },
    onError: (error: unknown) =>
      announce(`해시 계산 실패: ${error instanceof Error ? error.message : String(error)}`, {
        politeness: "assertive",
      }),
  });
  // Folder evidence (no size) is never hashed; a running hash cannot be restarted.
  if (item.size_bytes === null || !REHASH_FROM.has(item.hash_status)) return null;
  const label = item.hash_status === "not-requested" ? "해시 계산" : "해시 다시 계산";
  return (
    <ReasonButton
      className="button ghost"
      aria-label={`증거 ${item.evidence_number} ${label}`}
      reason={rehash.isPending ? "요청 중입니다" : undefined}
      onClick={() => rehash.mutate()}
    >
      {label}
    </ReasonButton>
  );
}

const SOURCE_KIND_LABEL: Record<string, string> = { image: "디스크 이미지", file: "파일", folder: "폴더" };

function itemCountText(counts: CanonicalCounts | undefined): string | null {
  const items = evidenceItemCount(counts);
  if (items === undefined) return null;
  return `${n(items)} (파일 ${n(counts?.files ?? 0)} + 아티팩트 ${n(counts?.artifacts ?? 0)})`;
}

function PartitionDetails({ source, onOpenFiles }: { source: EvidenceSource; onOpenFiles: () => void }) {
  if (!source.partitions.length) {
    return source.kind === "image" ? (
      <p className="dash-note">이미지 단계가 파티션 표를 기록하지 않았습니다.</p>
    ) : null;
  }
  const selected = source.partitions.find((partition) => partition.selected);
  return (
    <details className="dash-details">
      <summary>
        파티션 {n(source.partitions.length)}개 · 선택: {selected ? partitionLabel(selected) : "선택 안 됨"}
      </summary>
      <div className="dash-scroll">
        <table className="data-table dash-table" aria-label="파티션">
          <thead>
            <tr>
              <th scope="col">번호</th>
              <th scope="col">파일 시스템</th>
              <th scope="col">크기</th>
              <th scope="col">복구 대상</th>
            </tr>
          </thead>
          <tbody>
            {source.partitions.map((partition) => (
              <tr key={partition.number} className={partition.selected ? "selected" : undefined}>
                <td>{partition.number}</td>
                <td title={partition.description}>
                  {partition.filesystem === "unknown" ? "알 수 없음" : partition.filesystem.toUpperCase()}
                </td>
                <td>{formatBytes(partition.size_bytes)}</td>
                <td>
                  {partition.selected ? (
                    <button type="button" className="button ghost" onClick={onOpenFiles}>
                      선택됨 · 파일 보기
                    </button>
                  ) : (
                    <span className="dash-note">{partition.recommended ? "권장" : "선택 안 됨"}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

function CaseEvidenceItem({
  caseId,
  item,
  currentRunId,
  counts,
}: {
  caseId: string;
  item: CaseEvidence;
  currentRunId: string;
  counts: CanonicalCounts | undefined;
}) {
  const openDialog = useCaseDialogs((s) => s.openDialog);
  const isCurrent = item.runs.some((run) => run.run_id === currentRunId);
  const countText = isCurrent ? itemCountText(counts) : null;
  return (
    <li className="dash-evidence-item" data-current={isCurrent || undefined}>
      <p className="dash-evidence-line">
        <b className="dash-evidence-number">{item.evidence_number}</b>
        <span>{EVIDENCE_TYPE_LABEL[item.source_type] ?? item.source_type}</span>
        <span className="dash-wrap">{item.display_name}</span>
        <ToneChip tone={HASH_TONE[item.hash_status] ?? ""} title={item.hash_message || undefined}>
          {HASH_LABEL[item.hash_status] ?? item.hash_status_label}
        </ToneChip>
      </p>
      <p className="dash-note mono dash-wrap" title={item.path}>
        {item.path}
        {item.size_bytes !== null ? ` (${formatBytes(item.size_bytes)})` : ""}
      </p>
      {countText ? <p className="dash-note">항목 수 {countText}</p> : null}
      <div className="dash-evidence-runs">
        {item.runs.length === 0 ? (
          <span className="dash-note">런 없음</span>
        ) : (
          <ul className="dash-run-list" aria-label={`증거 ${item.evidence_number} 런`}>
            {item.runs.map((run, index) => {
              const label = run.run_id === currentRunId ? "이 런" : `런 ${index + 1}`;
              return (
                <li key={run.run_id}>
                  <a
                    className="dash-link"
                    href={serializeRoute({ runId: run.run_id, collection: "intake" })}
                    aria-current={run.run_id === currentRunId ? "page" : undefined}
                    aria-label={`증거 ${item.evidence_number} ${label} 열기`}
                    title={`런 ID ${run.run_id}`}
                  >
                    {label}
                  </a>{" "}
                  {run.exists ? (
                    <StatusBadge status={run.status} />
                  ) : (
                    <span className="dash-note">제거됨</span>
                  )}
                </li>
              );
            })}
          </ul>
        )}
        <span className="dash-evidence-actions">
          <EvidenceHashButton caseId={caseId} item={item} />
          {item.runnable === false ? (
            <span className="dash-note" data-testid="evidence-register-only">
              등록만
            </span>
          ) : null}
          <ReasonButton
            className="button ghost"
            aria-label={`증거 ${item.evidence_number} 런 시작`}
            reason={
              item.runnable === false
                ? item.run_blocked_reason || "바로 처리할 수 없는 증거입니다"
                : undefined
            }
            onClick={() => openDialog("run-add", { caseId, evidenceCitationId: item.citation_id })}
          >
            런 시작
          </ReasonButton>
        </span>
      </div>
    </li>
  );
}

/**
 * 증거: the case's evidence list (E-01 · 종류 · 이름 · 경로 · 항목 수 · 해시 · 런) merged with the run's
 * evidence source (항목 수, 파티션). Without a case it shows the run's own evidence source.
 */
export function EvidenceCard({
  detail,
  source,
  counts,
  currentRunId,
  onOpenFiles,
}: {
  detail: CaseDetail | null;
  source: EvidenceSource | undefined;
  counts: CanonicalCounts | undefined;
  currentRunId: string;
  onOpenFiles: () => void;
}) {
  const evidence = detail
    ? [...detail.evidence].sort((a, b) => koCompare(a.evidence_number, b.evidence_number))
    : [];
  return (
    <div className="dash-evidence" data-testid="case-evidence">
      {detail ? (
        evidence.length === 0 ? (
          <CardEmpty title="증거가 없습니다" compact>
            증거를 추가하면 증거마다 런을 시작할 수 있습니다
          </CardEmpty>
        ) : (
          <ul className="dash-evidence-list" aria-label="증거 목록">
            {evidence.map((item) => (
              <CaseEvidenceItem
                key={item.citation_id}
                caseId={detail.case_id}
                item={item}
                currentRunId={currentRunId}
                counts={counts}
              />
            ))}
          </ul>
        )
      ) : source ? (
        <div className="dash-evidence-item" data-current>
          <p className="dash-evidence-line">
            <span>{SOURCE_KIND_LABEL[source.kind] ?? source.kind}</span>
            <span className="dash-wrap">
              <b>{source.name}</b>
            </span>
          </p>
          <p className="dash-note mono dash-wrap" title={source.path}>
            {source.path || "—"}
            {source.size_bytes ? ` (${formatBytes(source.size_bytes)})` : ""}
          </p>
          <p className="dash-note">항목 수 {itemCountText(counts) ?? "런이 완료되면 표시됩니다"}</p>
          <CardEmpty title="케이스 없음" compact>
            케이스에 연결하면 증거 번호·해시·런 목록이 표시됩니다
          </CardEmpty>
        </div>
      ) : null}
      {source ? <PartitionDetails source={source} onOpenFiles={onOpenFiles} /> : null}
      {detail ? (
        <div className="dash-row">
          <CommandButton command="case.evidence.add" label="증거 추가" variant="ghost" showReason />
        </div>
      ) : null}
    </div>
  );
}

// --- 처리 설정 스냅샷 (처리 stage; no longer on 접수) -------------------------------------

const ORIGIN_NOTE: Record<string, string> = {
  "case-run": "런 시작 시 케이스에 고정된 처리 옵션입니다.",
  "linked-run": "케이스에 연결할 때 런 기록에서 옮긴 처리 옵션입니다.",
  "run-request": "케이스 없이 실행된 런 — 런 요청 기준입니다 (케이스에 고정되지 않음).",
};

/**
 * 처리 설정 스냅샷: the options fixed for this run. Removed from the 접수 dashboard (r7: the status
 * strip links "처리 설정 보기" to the 처리 stage); kept here for the 처리 stage to mount.
 */
export function SnapshotCard({ snapshot }: { snapshot: ProcessingSnapshot }) {
  const body = snapshot.snapshot;
  const rows = summarizeRunRequest(body.request ?? null);
  const keywords = body.profile?.keywords ?? [];
  const kinds = body.profile?.artifacts_kinds ?? [];
  return (
    <div className="dash-snapshot" data-testid="snapshot">
      <p className="dash-note">{ORIGIN_NOTE[String(body.origin)] ?? ORIGIN_NOTE["run-request"]}</p>
      <dl className="detail-grid dash-facts">
        <dt>고정 시각</dt>
        <dd>{formatTime(snapshot.captured_at)}</dd>
        {body.evidence?.evidence_number ? (
          <>
            <dt>증거</dt>
            <dd>
              {body.evidence.evidence_number} <span className="mono dash-wrap">{body.evidence.path}</span>
            </dd>
          </>
        ) : null}
        {keywords.length ? (
          <>
            <dt>프로필 키워드</dt>
            <dd>{[...keywords].sort(koCompare).join(", ")}</dd>
          </>
        ) : null}
        {kinds.length ? (
          <>
            <dt>수집 계열</dt>
            <dd>{n(kinds.length)}종</dd>
          </>
        ) : null}
        {body.file ? (
          <>
            <dt>스냅샷 파일</dt>
            <dd className="mono dash-wrap">{body.file}</dd>
          </>
        ) : null}
      </dl>
      <div className="dash-scroll">
        <table className="data-table dash-table" aria-label="처리 설정 스냅샷">
          <tbody>
            {rows.map((row) => (
              <tr key={row.key} data-key={row.key}>
                <th scope="row">{row.label}</th>
                <td className={row.key === "output_dir" ? "mono dash-wrap" : "dash-wrap"}>{row.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --- 처리 경고·제한 사항 ------------------------------------------------------------

export interface WarningCounts {
  /** 경고: error + warning problems (or non-notice step warnings without /problems). */
  warn: number;
  /** 알림: notice problems. */
  notice: number;
  /** 제한: warn-tone disclosure lines (확인 필요 사항). */
  limit: number;
}

export function warningCounts(
  problems: RunProblems | undefined,
  items: DisclosureItem[],
  warnings: RunWarning[],
): WarningCounts {
  const limit = items.filter((item) => item.tone === "warn").length;
  if (problems) {
    const by = problems.by_level ?? {};
    return { warn: (by.error ?? 0) + (by.warning ?? 0), notice: by.notice ?? 0, limit };
  }
  const notice = warnings.filter(isNotice).length;
  return { warn: warnings.length - notice, notice, limit };
}

export const warningCountsText = (counts: WarningCounts) =>
  `경고 ${n(counts.warn)} · 알림 ${n(counts.notice)} · 제한 ${n(counts.limit)}`;

function ProblemGroups({ runId, problems }: { runId: string; problems: RunProblems }) {
  const openDialog = useCaseDialogs((s) => s.openDialog);
  return (
    <ul className="dash-problems" aria-label="처리 경고·알림 사유별" data-testid="problems">
      {problems.groups.map((group) => (
        <li key={group.reason_id} className="dash-problem">
          <details>
            <summary>
              <ToneChip tone={LEVEL_TONE[group.level] ?? ""}>
                {LEVEL_LABEL[group.level] ?? group.level}
              </ToneChip>{" "}
              <span className="dash-problem-label">{group.label_ko}</span>{" "}
              <span className="badge muted">{n(group.count)}</span>
            </summary>
            <ul className="dash-issues" aria-label={`${group.label_ko} 미리보기`}>
              {group.items.map((item, index) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: problem items have no id; order is stable
                <li key={index} title={item.message}>
                  {item.step ? (
                    <span className="dash-issue-step" title={item.step}>
                      {stepLabelKo(item.step)}
                    </span>
                  ) : null}{" "}
                  {problemMessageKo(item.message)}
                </li>
              ))}
            </ul>
            {group.count > group.items.length ? (
              <p className="dash-note">
                미리보기 {n(group.items.length)}건 / 전체 {n(group.count)}건
              </p>
            ) : null}
          </details>
          <button
            type="button"
            className="button ghost"
            aria-label={`${group.label_ko} 전체 보기 (${n(group.count)}건)`}
            onClick={() =>
              openDialog("problems", { runId, reasonId: group.reason_id, reasonLabel: group.label_ko })
            }
          >
            전체 보기
          </button>
        </li>
      ))}
    </ul>
  );
}

/**
 * 처리 경고·제한 사항 (merges 처리 문제 + 단계 경고 + 공개 사항): 처리 경고·알림 by reason (collapsed),
 * then 처리 제한 사항 (warn-tone lines = 확인 필요 사항, each collapsed), then the info-tone lines in a
 * collapsed "공개 사항(정보)". `/problems` already groups the step warnings; the raw `warnings[]`
 * list is only the fallback when /problems is unavailable.
 */
export function WarningsCard({
  runId,
  problems,
  items,
  warnings,
}: {
  runId: string;
  problems: RunProblems | undefined;
  items: DisclosureItem[];
  warnings: RunWarning[];
}) {
  const warnHeadingId = useId();
  const limitHeadingId = useId();
  const limits = items.filter((item) => item.tone === "warn");
  const info = items.filter((item) => item.tone !== "warn");
  const hasProblems = problems ? problems.total > 0 : warnings.length > 0;
  return (
    <div className="dash-warnings" data-testid="warnings-card">
      <section className="dash-section" aria-labelledby={warnHeadingId}>
        <h3 className="dash-subhead" id={warnHeadingId}>
          처리 경고·알림
        </h3>
        {!hasProblems ? (
          <CardEmpty title="처리 경고·알림 없음" compact>
            경고·파서 오류·실패 단계가 기록되지 않았습니다
          </CardEmpty>
        ) : problems ? (
          <ProblemGroups runId={runId} problems={problems} />
        ) : (
          <details className="dash-details">
            <summary>{warningsSummary(warnings)}</summary>
            <WarningList warnings={warnings} />
          </details>
        )}
      </section>
      <section className="dash-section" aria-labelledby={limitHeadingId}>
        <h3 className="dash-subhead" id={limitHeadingId}>
          처리 제한 사항
        </h3>
        {limits.length === 0 ? (
          <CardEmpty title="확인 필요 사항 없음" compact>
            {items.length ? "아래 정보만 기록되었습니다" : "이 런의 요약에는 처리 제한 사항이 없습니다"}
          </CardEmpty>
        ) : (
          <ul className="dash-limits" aria-label="확인 필요 사항">
            {limits.map((item) => (
              <li key={item.id}>
                <details className="dash-limit" title={item.detail}>
                  <summary>
                    <ToneChip tone="warn">{item.label}</ToneChip>
                  </summary>
                  <p className="dash-limit-text">{item.text}</p>
                </details>
              </li>
            ))}
          </ul>
        )}
        {info.length ? (
          <details className="dash-details" data-testid="disclosures-info">
            <summary>공개 사항(정보) {n(info.length)}건</summary>
            <DisclosureList items={info} label="공개 사항(정보)" />
          </details>
        ) : null}
      </section>
    </div>
  );
}

// --- 노트·메모 (케이스 메모 + 요약 노트, 검사관 한 칸) ---------------------------------------

/**
 * 노트·메모: one 검사관 field drives both the memo author and the run's 요약 노트 examiner. 케이스 메모
 * (작성자 · 시각 · 이력, case DB) is on top; the 요약 노트 (PUT /case-notes, fills the report's 분석자 ·
 * 분석 범위) is collapsed below.
 */
export function NotesCard({
  runId,
  caseId,
  caseExaminer,
  caseNotes,
  caseNotesState,
  runNotes,
}: {
  runId: string;
  caseId: string | null;
  caseExaminer: string;
  caseNotes: CaseNotes | undefined;
  caseNotesState: "loading" | "error" | "ready" | "none";
  runNotes: RunNotes | undefined;
}) {
  const client = useQueryClient();
  const examinerId = useId();
  const textId = useId();
  const summaryId = useId();
  const noteStateId = useId();
  const [examinerEdit, setExaminerEdit] = useState<string | null>(null);
  const [summaryEdit, setSummaryEdit] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [showHistory, setShowHistory] = useState(false);
  const examiner = examinerEdit ?? (runNotes?.examiner || caseExaminer);
  const summary = summaryEdit ?? runNotes?.summary ?? "";
  const dirty = examinerEdit !== null || summaryEdit !== null;

  const refreshCase = () => {
    if (!caseId) return;
    void client.invalidateQueries({ queryKey: caseNotesQueryKey(caseId) });
    void client.invalidateQueries({ queryKey: caseQueryKey(caseId) });
  };
  const add = useMutation({
    mutationFn: () => addCaseNote(caseId as string, { text: text.trim(), author: examiner.trim() }),
    onSuccess: () => {
      setText("");
      refreshCase();
      announce("케이스 메모를 추가했습니다");
    },
    onError: (error: unknown) =>
      announce(`메모 추가 실패: ${error instanceof Error ? error.message : String(error)}`, {
        politeness: "assertive",
      }),
  });
  const remove = useMutation({
    mutationFn: (noteId: number) => deleteCaseNote(caseId as string, noteId, examiner.trim()),
    onSuccess: () => {
      refreshCase();
      announce("메모를 삭제했습니다 (이력에 남음)");
    },
  });
  const save = useMutation<RunNotes, Error>({
    mutationFn: () => saveCaseNotes(runId, { examiner, summary }),
    onSuccess: (saved) => {
      client.setQueryData(["case-notes", runId], saved);
      setExaminerEdit(null);
      setSummaryEdit(null);
      announce("요약 노트를 저장했습니다");
    },
    onError: (error: unknown) =>
      announce(`노트 저장 실패: ${error instanceof Error ? error.message : String(error)}`, {
        politeness: "assertive",
      }),
  });
  const onAdd = (event: FormEvent) => {
    event.preventDefault();
    if (text.trim() && !add.isPending) add.mutate();
  };
  const onSave = (event: FormEvent) => {
    event.preventDefault();
    if (!save.isPending && dirty) save.mutate();
  };
  const history = caseNotes?.history ?? [];

  return (
    <div className="dash-memo" data-testid="case-memo">
      <div className="dash-notes dash-examiner">
        <label htmlFor={examinerId}>검사관</label>
        <input
          id={examinerId}
          className="dash-input"
          maxLength={200}
          value={examiner}
          placeholder="예: 홍길동 (디지털포렌식팀)"
          onChange={(event) => setExaminerEdit(event.target.value)}
        />
      </div>

      <section className="dash-section" aria-label="케이스 메모">
        <h3 className="dash-subhead">
          케이스 메모{caseNotes ? <span className="dash-note"> · {n(caseNotes.count)}건</span> : null}
        </h3>
        {!caseId ? (
          <CardEmpty title="케이스 없음" compact>
            케이스에 연결하면 검사관·시각이 남는 케이스 메모를 쓸 수 있습니다
          </CardEmpty>
        ) : caseNotesState === "loading" ? (
          <p className="dash-note">불러오는 중…</p>
        ) : caseNotesState === "error" || !caseNotes ? (
          <p className="error-banner">케이스 메모를 불러오지 못했습니다.</p>
        ) : (
          <>
            {caseNotes.notes.length === 0 ? (
              <CardEmpty title="메모 없음" compact />
            ) : (
              <ul className="dash-memo-list" aria-label="케이스 메모">
                {caseNotes.notes.map((note) => (
                  <li key={note.id} className="dash-memo-item">
                    <p className="dash-memo-meta">
                      <strong>{note.author || "검사관 미지정"}</strong> ·{" "}
                      <time dateTime={note.created_at}>{formatTime(note.created_at)}</time>
                    </p>
                    <p className="dash-memo-text">{note.text}</p>
                    <button
                      type="button"
                      className="button ghost"
                      aria-label={`${note.author || "검사관 미지정"} 메모 삭제 (${formatTime(note.created_at)})`}
                      onClick={() => remove.mutate(note.id)}
                    >
                      삭제
                    </button>
                  </li>
                ))}
              </ul>
            )}
            <form className="dash-notes" onSubmit={onAdd} aria-busy={add.isPending}>
              <label htmlFor={textId} id={`${textId}-label`}>
                새 메모
              </label>
              <textarea
                id={textId}
                aria-labelledby={`${textId}-label`}
                className="dash-input"
                rows={2}
                maxLength={10000}
                value={text}
                onChange={(event) => setText(event.target.value)}
              />
              <div className="dash-notes-foot">
                <ReasonButton
                  type="submit"
                  className="button primary"
                  reason={
                    add.isPending ? "추가 중입니다" : !text.trim() ? "메모 내용을 입력하세요" : undefined
                  }
                >
                  {add.isPending ? "추가 중…" : "메모 추가"}
                </ReasonButton>
                <button
                  type="button"
                  className="button ghost"
                  aria-expanded={showHistory}
                  onClick={() => setShowHistory((value) => !value)}
                >
                  {`이력 ${n(history.length)}건${caseNotes.deleted_count ? ` · 삭제 ${n(caseNotes.deleted_count)}건` : ""}`}
                  {showHistory ? " 접기" : ""}
                </button>
              </div>
            </form>
            {add.isError ? (
              <p className="error-banner">
                추가하지 못했습니다: {add.error instanceof Error ? add.error.message : ""}
              </p>
            ) : null}
            {showHistory ? (
              <ol className="dash-memo-history" aria-label="메모 이력">
                {history.map((entry) => (
                  <li key={entry.id}>
                    <time dateTime={entry.at}>{formatTime(entry.at)}</time> · {entry.actor || "검사관 미지정"}{" "}
                    · {entry.action === "deleted" ? "삭제" : "작성"} —{" "}
                    <span className="dash-memo-text">{entry.text}</span>
                  </li>
                ))}
              </ol>
            ) : null}
          </>
        )}
      </section>

      <details className="dash-details" data-testid="summary-note">
        <summary>
          요약 노트 —{" "}
          {dirty
            ? "저장하지 않은 변경"
            : runNotes?.updated_at
              ? `저장됨 · ${formatTime(runNotes.updated_at)}`
              : "저장된 노트 없음"}
        </summary>
        <form className="dash-notes" onSubmit={onSave} aria-busy={save.isPending}>
          <label htmlFor={summaryId} id={`${summaryId}-label`}>
            케이스 요약
          </label>
          <textarea
            id={summaryId}
            aria-labelledby={`${summaryId}-label`}
            className="dash-input"
            rows={3}
            maxLength={20000}
            value={summary}
            placeholder="사건 개요, 분석 목적, 주의할 점을 적어 두면 보고서의 분석 범위에 들어갑니다."
            onChange={(event) => setSummaryEdit(event.target.value)}
          />
          <div className="dash-notes-foot">
            <button
              type="submit"
              className="button primary"
              aria-disabled={save.isPending || !dirty || undefined}
              aria-describedby={save.isPending || !dirty ? noteStateId : undefined}
            >
              {save.isPending ? "저장 중…" : "요약 노트 저장"}
            </button>
            {/* Saves/failures are announced through the shell live region (announce()). */}
            <span className="dash-note" id={noteStateId}>
              {dirty
                ? "저장하지 않은 변경이 있습니다"
                : runNotes?.updated_at
                  ? `저장됨 · ${formatTime(runNotes.updated_at)}`
                  : "아직 저장된 노트가 없습니다"}
            </span>
          </div>
          {save.isError ? (
            <p className="error-banner">
              저장하지 못했습니다: {save.error instanceof Error ? save.error.message : String(save.error)}
            </p>
          ) : null}
          <p className="dash-note">
            검사관 이름과 요약은 케이스 보고서의 분석자·분석 범위가 비어 있을 때 채워집니다.
          </p>
        </form>
      </details>
    </div>
  );
}
