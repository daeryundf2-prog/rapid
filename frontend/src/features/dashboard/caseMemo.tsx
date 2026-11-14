/**
 * 접수 노트·메모 block (split out of caseCards.tsx): one examiner field, 케이스 메모 (작성자 · 시각 ·
 * 이력, case DB) with inline delete confirmation, the collapsed 요약 노트, the Korean failure text
 * of memo requests (T-144) and the unsaved-input leave guard.
 */

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useEffect, useId, useRef, useState } from "react";
import { announce } from "../../a11y";
import { addCaseNote, type CaseNotes, deleteCaseNote } from "../../api/cases";
import { type CaseNotes as RunNotes, saveCaseNotes } from "../../api/dashboard";
import { ApiError } from "../../api/errors";
import type { Route } from "../../router";
import { readOnlyErrorSentence, useWriteBlock } from "../../shell/readOnly";
import { registerLeaveGuard, UNSAVED_LEAVE_MESSAGE } from "../../state/leaveGuard";
import { InlineConfirm } from "../case/InlineConfirm";
import { ReasonButton } from "../case/ReasonButton";
import { CardEmpty } from "./Card";
import { caseNotesQueryKey, caseQueryKey } from "./caseCards";
import { formatTime } from "./model";

const n = (value: number) => value.toLocaleString("ko-KR");

const HANGUL = /[가-힣]/;

/**
 * Korean sentence for a failed memo request (T-144): "{action} 못했습니다. {why}" — the ApiError's
 * Korean message when it has one, else a generic Korean reason; never the raw English text of a
 * browser or server error.
 */
export function memoFailureText(action: string, error: unknown): string {
  const readOnly = readOnlyErrorSentence(error); // T-348: the band's sentence, not a failure
  if (readOnly) return readOnly;
  const why =
    error instanceof ApiError && HANGUL.test(error.message) && !/[A-Za-z]{3,}/.test(error.message)
      ? error.message.replace(/[.。]\s*$/, "")
      : "서버가 요청을 처리하지 않았습니다";
  return `${action} 못했습니다. ${why}. 잠시 뒤 다시 시도하세요.`;
}

/** True when moving `prev → next` leaves this run's 접수 dashboard (where the memo block lives). */
function leavesDashboard(prev: Route, next: Route): boolean {
  return next.runId !== prev.runId || next.collection !== prev.collection;
}

/**
 * 노트·메모: one examiner field drives both the memo author and the run's 요약 노트 examiner. 케이스 메모
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
  // Unsaved input of the block: the examiner and 요약 edits and a typed but not yet added memo.
  const unsaved = dirty || text.trim() !== "";
  useEffect(() => {
    if (!unsaved) return;
    const unregister = registerLeaveGuard((prev, next) =>
      leavesDashboard(prev, next) ? UNSAVED_LEAVE_MESSAGE : null,
    );
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => {
      unregister();
      window.removeEventListener("beforeunload", onBeforeUnload);
    };
  }, [unsaved]);

  const refreshCase = () => {
    if (!caseId) return;
    void client.invalidateQueries({ queryKey: caseNotesQueryKey(caseId) });
    void client.invalidateQueries({ queryKey: caseQueryKey(caseId) });
  };
  // T-348: case memos live in the case workspace; the summary note in the result folder.
  const caseWriteBlock = useWriteBlock("server");
  const runWriteBlock = useWriteBlock("run");
  const add = useMutation({
    mutationFn: () => addCaseNote(caseId as string, { text: text.trim(), author: examiner.trim() }),
    onSuccess: () => {
      setText("");
      refreshCase();
      announce("케이스 메모를 추가했습니다");
    },
    onError: (error: unknown) =>
      announce(memoFailureText("메모를 추가하지", error), { politeness: "assertive" }),
  });
  // Memo delete asks first (T-034): 삭제 opens an inline confirmation on that memo.
  const [confirmNoteId, setConfirmNoteId] = useState<number | null>(null);
  const deleteButtons = useRef(new Map<number, HTMLButtonElement>());
  const cancelDelete = () => {
    const opener = confirmNoteId === null ? undefined : deleteButtons.current.get(confirmNoteId);
    setConfirmNoteId(null);
    opener?.focus();
  };
  const remove = useMutation({
    mutationFn: (noteId: number) => deleteCaseNote(caseId as string, noteId, examiner.trim()),
    onSuccess: () => {
      setConfirmNoteId(null);
      refreshCase();
      announce("메모를 삭제했습니다 (이력에 남음)");
    },
    onError: (error: unknown) =>
      announce(memoFailureText("메모를 삭제하지", error), { politeness: "assertive" }),
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
      announce(memoFailureText("요약 노트를 저장하지", error), { politeness: "assertive" }),
  });
  const onAdd = (event: FormEvent) => {
    event.preventDefault();
    if (text.trim() && !add.isPending && !caseWriteBlock) add.mutate();
  };
  const onSave = (event: FormEvent) => {
    event.preventDefault();
    if (!save.isPending && dirty && !runWriteBlock) save.mutate();
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
                      ref={(element) => {
                        if (element) deleteButtons.current.set(note.id, element);
                        else deleteButtons.current.delete(note.id);
                      }}
                      type="button"
                      className="button ghost"
                      aria-label={`${note.author || "검사관 미지정"} 메모 삭제 (${formatTime(note.created_at)})`}
                      aria-expanded={confirmNoteId === note.id}
                      aria-disabled={caseWriteBlock ? true : undefined}
                      title={caseWriteBlock}
                      onClick={() => {
                        if (caseWriteBlock) return;
                        remove.reset();
                        setConfirmNoteId(note.id);
                      }}
                    >
                      삭제
                    </button>
                    {confirmNoteId === note.id ? (
                      <InlineConfirm
                        label="메모 삭제 확인"
                        testId="memo-delete"
                        className="dash-memo-confirm"
                        busy={remove.isPending}
                        onCancel={cancelDelete}
                        onConfirm={() => remove.mutate(note.id)}
                      >
                        <p>
                          이 메모를 케이스 메모 목록에서 지웁니다. 메모 이력에는 삭제 기록으로 남고, 원본
                          증거와 처리 결과는 바뀌지 않습니다.
                        </p>
                        {remove.isError ? (
                          <p className="error-banner" data-testid="memo-delete-error">
                            {memoFailureText("메모를 삭제하지", remove.error)}
                          </p>
                        ) : null}
                      </InlineConfirm>
                    ) : null}
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
                    caseWriteBlock ??
                    (add.isPending ? "추가 중입니다" : !text.trim() ? "메모 내용을 입력하세요" : undefined)
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
              <p className="error-banner" data-testid="memo-add-error">
                {memoFailureText("메모를 추가하지", add.error)}
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
              aria-disabled={save.isPending || !dirty || Boolean(runWriteBlock) || undefined}
              title={runWriteBlock}
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
            <p className="error-banner" data-testid="summary-save-error">
              {memoFailureText("요약 노트를 저장하지", save.error)}
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
