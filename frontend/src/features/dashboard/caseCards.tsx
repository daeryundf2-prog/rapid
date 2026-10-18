/**
 * 접수 case cards (AXIOM adoption E1, plan §3.1): 사건 정보 (편집) · 증거 목록 (런 상태 · 런 추가) ·
 * 처리 설정 스냅샷 · 처리 문제 (사유별, 미리보기 ≤ 20, 전체 보기) · 케이스 메모 (작성자 · 시각 · 이력).
 * A run without a case keeps working: 사건 정보 offers "케이스에 연결", 증거/메모 explain why they
 * are empty, the snapshot reads the run request and the problems card reads the run summary.
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
import { CommandButton } from "../../commands/CommandButton";
import { StatusBadge } from "../../components/Badge";
import { ToneChip } from "../../components/ToneChip";
import { serializeRoute } from "../../router";
import { LEVEL_LABEL } from "../case/CaseDialogs";
import { useCaseDialogs } from "../case/dialogs";
import { ReasonButton } from "../case/ReasonButton";
import { summarizeRunRequest } from "../case/runSummary";
import { EVIDENCE_TYPE_LABEL } from "../case/wizardModel";
import { formatBytes } from "../tree/model";
import { CardEmpty } from "./Card";
import { formatTime } from "./model";

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
      <dl className="detail-grid">
        {rows.map(([label, value]) => (
          <Fragment key={label}>
            <dt>{label}</dt>
            <dd
              className={label === "케이스 폴더" || label === "인용 ID 접두" ? "mono break-all" : undefined}
            >
              {value || "—"}
            </dd>
          </Fragment>
        ))}
      </dl>
      <div className="dash-row">
        <CommandButton command="case.edit" label="편집" showReason />
      </div>
    </div>
  );
}

// --- 증거 목록 -------------------------------------------------------------------

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

export function CaseEvidenceCard({ detail, currentRunId }: { detail: CaseDetail; currentRunId: string }) {
  const openDialog = useCaseDialogs((s) => s.openDialog);
  const evidence = [...detail.evidence].sort((a, b) => koCompare(a.evidence_number, b.evidence_number));
  return (
    <div className="dash-case-evidence" data-testid="case-evidence">
      {evidence.length === 0 ? (
        <CardEmpty title="증거가 없습니다">증거를 추가하면 증거마다 런을 시작할 수 있습니다.</CardEmpty>
      ) : (
        <table className="data-table dash-table" aria-label="증거 목록">
          <thead>
            <tr>
              <th scope="col">증거 번호</th>
              <th scope="col">종류 · 이름</th>
              <th scope="col">해시</th>
              <th scope="col">런</th>
              <th scope="col">
                <span className="visually-hidden">동작</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {evidence.map((item) => (
              <tr key={item.citation_id}>
                <th scope="row">{item.evidence_number}</th>
                <td>
                  <span>{EVIDENCE_TYPE_LABEL[item.source_type] ?? item.source_type}</span>
                  <span className="dash-note"> · {item.display_name}</span>
                  <div className="dash-note mono break-all" title={item.path}>
                    {item.path}
                    {item.size_bytes !== null ? ` (${formatBytes(item.size_bytes)})` : ""}
                  </div>
                </td>
                <td>
                  <ToneChip tone={HASH_TONE[item.hash_status] ?? ""} title={item.hash_message || undefined}>
                    {item.hash_status_label}
                  </ToneChip>
                  <EvidenceHashButton caseId={detail.case_id} item={item} />
                </td>
                <td>
                  {item.runs.length === 0 ? (
                    <span className="dash-note">런 없음</span>
                  ) : (
                    <ul className="dash-run-list" aria-label={`증거 ${item.evidence_number} 런`}>
                      {item.runs.map((run) => (
                        <li key={run.run_id}>
                          <a
                            className="dash-link"
                            href={serializeRoute({ runId: run.run_id, collection: "intake" })}
                            aria-current={run.run_id === currentRunId ? "page" : undefined}
                            aria-label={`증거 ${item.evidence_number} 런 ${run.run_id.slice(0, 8)} 열기`}
                          >
                            {run.run_id.slice(0, 8)}
                          </a>{" "}
                          {run.exists ? (
                            <StatusBadge status={run.status} />
                          ) : (
                            <span className="dash-note">제거됨</span>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                </td>
                <td>
                  {item.runnable === false ? (
                    <span className="dash-note" data-testid="evidence-register-only">
                      등록만
                    </span>
                  ) : null}
                  <ReasonButton
                    className="button ghost"
                    aria-label={`증거 ${item.evidence_number} 런 추가`}
                    reason={
                      item.runnable === false
                        ? item.run_blocked_reason || "바로 처리할 수 없는 증거입니다"
                        : undefined
                    }
                    onClick={() =>
                      openDialog("run-add", { caseId: detail.case_id, evidenceCitationId: item.citation_id })
                    }
                  >
                    런 추가
                  </ReasonButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="dash-row">
        <CommandButton command="case.evidence.add" label="증거 추가" showReason />
      </div>
    </div>
  );
}

// --- 처리 설정 스냅샷 ------------------------------------------------------------

const ORIGIN_NOTE: Record<string, string> = {
  "case-run": "런 시작 시 케이스에 고정된 처리 옵션입니다.",
  "linked-run": "케이스에 연결할 때 런 기록에서 옮긴 처리 옵션입니다.",
  "run-request": "케이스 없이 실행된 런 — 런 요청 기준입니다 (케이스에 고정되지 않음).",
};

export function SnapshotCard({ snapshot }: { snapshot: ProcessingSnapshot }) {
  const body = snapshot.snapshot;
  const rows = summarizeRunRequest(body.request ?? null);
  const keywords = body.profile?.keywords ?? [];
  const kinds = body.profile?.artifacts_kinds ?? [];
  return (
    <div className="dash-snapshot" data-testid="snapshot">
      <p className="dash-note">{ORIGIN_NOTE[String(body.origin)] ?? ORIGIN_NOTE["run-request"]}</p>
      <dl className="detail-grid">
        <dt>고정 시각</dt>
        <dd>{formatTime(snapshot.captured_at)}</dd>
        {body.evidence?.evidence_number ? (
          <>
            <dt>증거</dt>
            <dd>
              {body.evidence.evidence_number} <span className="mono break-all">{body.evidence.path}</span>
            </dd>
          </>
        ) : body.request?.root ? (
          <>
            <dt>증거 경로</dt>
            <dd className="mono break-all">{String(body.request.root)}</dd>
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
            <dt>스냅숏 파일</dt>
            <dd className="mono break-all">{body.file}</dd>
          </>
        ) : null}
      </dl>
      <table className="data-table dash-table" aria-label="처리 설정 스냅샷">
        <tbody>
          {rows.map((row) => (
            <tr key={row.key} data-key={row.key}>
              <th scope="row">{row.label}</th>
              <td className={row.key === "output_dir" ? "mono break-all" : undefined}>{row.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// --- 처리 문제 -------------------------------------------------------------------

export function ProblemsCard({ runId, problems }: { runId: string; problems: RunProblems }) {
  const openDialog = useCaseDialogs((s) => s.openDialog);
  if (problems.total === 0) {
    return <CardEmpty title="처리 문제 없음">경고·파서 오류·실패 단계가 기록되지 않았습니다.</CardEmpty>;
  }
  return (
    <ul className="dash-problems" aria-label="처리 문제 사유별" data-testid="problems">
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
                <li key={index}>
                  {item.step ? <span className="mono">{item.step}</span> : null} {item.message}
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

// --- 케이스 메모 -----------------------------------------------------------------

export function CaseMemoCard({
  caseId,
  examiner,
  notes,
}: {
  caseId: string;
  examiner: string;
  notes: CaseNotes;
}) {
  const client = useQueryClient();
  const textId = useId();
  const authorId = useId();
  const [text, setText] = useState("");
  const [author, setAuthor] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);
  const authorValue = author ?? examiner;
  const refresh = () => {
    void client.invalidateQueries({ queryKey: caseNotesQueryKey(caseId) });
    void client.invalidateQueries({ queryKey: caseQueryKey(caseId) });
  };
  const add = useMutation({
    mutationFn: () => addCaseNote(caseId, { text: text.trim(), author: authorValue.trim() }),
    onSuccess: () => {
      setText("");
      refresh();
      announce("케이스 메모를 추가했습니다");
    },
    onError: (error: unknown) =>
      announce(`메모 추가 실패: ${error instanceof Error ? error.message : String(error)}`, {
        politeness: "assertive",
      }),
  });
  const remove = useMutation({
    mutationFn: (noteId: number) => deleteCaseNote(caseId, noteId, authorValue.trim()),
    onSuccess: () => {
      refresh();
      announce("메모를 삭제했습니다 (이력에 남음)");
    },
  });
  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (text.trim() && !add.isPending) add.mutate();
  };
  const reason = !text.trim() ? "메모 내용을 입력하세요" : undefined;

  return (
    <div className="dash-memo" data-testid="case-memo">
      {notes.notes.length === 0 ? (
        <p className="dash-note">아직 메모가 없습니다.</p>
      ) : (
        <ul className="dash-memo-list" aria-label="케이스 메모">
          {notes.notes.map((note) => (
            <li key={note.id} className="dash-memo-item">
              <p className="dash-memo-meta">
                <strong>{note.author || "작성자 미지정"}</strong> ·{" "}
                <time dateTime={note.created_at}>{formatTime(note.created_at)}</time>
              </p>
              <p className="dash-memo-text">{note.text}</p>
              <button
                type="button"
                className="button ghost"
                aria-label={`${note.author || "작성자 미지정"} 메모 삭제 (${formatTime(note.created_at)})`}
                onClick={() => remove.mutate(note.id)}
              >
                삭제
              </button>
            </li>
          ))}
        </ul>
      )}
      <form className="dash-notes" onSubmit={onSubmit} aria-busy={add.isPending}>
        <label htmlFor={textId}>새 메모</label>
        <textarea
          id={textId}
          className="dash-input"
          rows={3}
          maxLength={10000}
          value={text}
          onChange={(event) => setText(event.target.value)}
        />
        <div className="dash-notes-foot">
          <label htmlFor={authorId}>작성자</label>
          <input
            id={authorId}
            className="dash-input"
            style={{ inlineSize: "auto", flex: 1 }}
            maxLength={200}
            value={authorValue}
            placeholder="검사관"
            onChange={(event) => setAuthor(event.target.value)}
          />
          <ReasonButton
            type="submit"
            className="button primary"
            reason={add.isPending ? "추가 중입니다" : reason}
          >
            {add.isPending ? "추가 중…" : "메모 추가"}
          </ReasonButton>
        </div>
      </form>
      {add.isError ? (
        <p className="error-banner">
          추가하지 못했습니다: {add.error instanceof Error ? add.error.message : ""}
        </p>
      ) : null}
      <button
        type="button"
        className="button ghost"
        aria-expanded={showHistory}
        onClick={() => setShowHistory((value) => !value)}
      >
        이력 {showHistory ? "접기" : `보기 (${n(notes.history.length)}건 · 삭제 ${n(notes.deleted_count)}건)`}
      </button>
      {showHistory ? (
        <ol className="dash-memo-history" aria-label="메모 이력">
          {notes.history.map((entry) => (
            <li key={entry.id}>
              <time dateTime={entry.at}>{formatTime(entry.at)}</time> · {entry.actor || "작성자 미지정"} ·{" "}
              {entry.action === "deleted" ? "삭제" : "작성"} —{" "}
              <span className="dash-memo-text">{entry.text}</span>
            </li>
          ))}
        </ol>
      ) : null}
    </div>
  );
}
