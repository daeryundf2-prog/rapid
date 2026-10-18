/**
 * 메모·이력 (AXIOM E3): one row's note with its author and time, a form to save a new note
 * under the configured author, and the mark's change history (author · time · what changed,
 * note before → after) from the case DB's append-only review_mark_history. A Modal: Esc
 * closes, focus returns to the opener.
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { announce } from "../../a11y";
import { getReviewHistory, type ReviewHistoryEntry } from "../../api/reviewTools";
import { useTimezone } from "../../state/hooks";
import { formatTimestamp } from "../../utils/time";
import { ErrorText } from "../case/ErrorText";
import { Modal } from "../case/Modal";
import { ReasonButton } from "../case/ReasonButton";
import { applyNote, reviewLocatorTarget, storeNotice } from "../grid/reviewActions";
import { noteKey, setSessionNote } from "../grid/sessionNotes";
import { currentReviewer, DEFAULT_REVIEWER, setReviewer } from "./author";
import type { NotePanelTarget } from "./uiStore";
import "./review.css";

const FIELD_LABELS: Record<string, string> = {
  note: "메모",
  tags: "태그",
  status: "상태",
  include_in_report: "보고서 포함",
  verification_status: "검증",
  reviewer: "작성자",
  assignee: "담당자",
  priority: "우선순위",
  due_at: "기한",
  source_citation_package: "인용 패키지",
};

const STATUS_LABELS: Record<string, string> = {
  unreviewed: "미검토",
  relevant: "관련 있음",
  "needs-review": "재검토",
  excluded: "제외",
};

/** "메모, 태그" — the changed fields of a history entry in Korean (unknown names kept). */
export function changedLabel(entry: ReviewHistoryEntry): string {
  const names = entry.changed_fields
    .filter((field) => field !== "reviewer")
    .map((field) => FIELD_LABELS[field] ?? field);
  return names.length ? names.join(", ") : "변경 없음";
}

function HistoryItem({ entry, timezone }: { entry: ReviewHistoryEntry; timezone: string }) {
  const when = formatTimestamp(entry.changed_at, timezone);
  const noteChanged = entry.changed_fields.includes("note");
  const tagsChanged = entry.changed_fields.includes("tags");
  const statusChanged = entry.changed_fields.includes("status");
  return (
    <li className="note-history-item" data-testid="note-history-item">
      <p className="note-history-head">
        <strong>{entry.author || "작성자 없음"}</strong> · <time dateTime={entry.changed_at}>{when}</time> ·{" "}
        {changedLabel(entry)}
      </p>
      {noteChanged ? (
        <p className="note-history-body">
          {entry.note_before ? (
            <>
              <span className="note-history-old">{entry.note_before}</span> →{" "}
            </>
          ) : null}
          <span>{entry.note_after || "(메모 지움)"}</span>
        </p>
      ) : null}
      {tagsChanged ? (
        <p className="note-history-body">
          태그: {entry.tags_before.join(", ") || "없음"} → {entry.tags_after.join(", ") || "없음"}
        </p>
      ) : null}
      {statusChanged ? (
        <p className="note-history-body">
          상태: {STATUS_LABELS[entry.status_before] ?? (entry.status_before || "없음")} →{" "}
          {STATUS_LABELS[entry.status_after] ?? entry.status_after}
        </p>
      ) : null}
    </li>
  );
}

export function NotePanel({ target, onClose }: { target: NotePanelTarget; onClose: () => void }) {
  const { runId, row } = target;
  const { timezone } = useTimezone();
  const queryClient = useQueryClient();
  const locator = reviewLocatorTarget(row);
  const history = useQuery({
    queryKey: ["review-history", runId, row.rowKey],
    queryFn: ({ signal }) =>
      locator
        ? getReviewHistory(runId, locator, signal)
        : Promise.resolve({ entries: [] as ReviewHistoryEntry[] }),
    retry: false,
  });
  const entries = history.data?.entries ?? [];
  const lastNote = entries.find((entry) => entry.changed_fields.includes("note"));
  const current = typeof row.fields.note === "string" ? row.fields.note : (lastNote?.note_after ?? "");
  const [text, setText] = useState(current);
  const [author, setAuthor] = useState(() =>
    currentReviewer() === DEFAULT_REVIEWER ? "" : currentReviewer(),
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const noteId = useId();
  const authorId = useId();

  const save = async () => {
    setBusy(true);
    setError(null);
    setReviewer(author);
    try {
      const result = await applyNote(runId, [row], text);
      setSessionNote(noteKey(runId, row.ref), text.trim());
      announce(`메모를 저장했습니다 (작성자 ${currentReviewer()}).${storeNotice(result)}`);
      await queryClient.invalidateQueries({ queryKey: ["review-history", runId, row.rowKey] });
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
    } finally {
      setBusy(false);
    }
  };

  const reason = !locator
    ? "출처 위치를 알 수 없는 행에는 메모를 남길 수 없습니다"
    : !text.trim()
      ? "메모 내용을 입력하세요"
      : text.trim() === current.trim()
        ? "바뀐 내용이 없습니다"
        : busy
          ? "저장하는 중입니다"
          : undefined;

  return (
    <Modal
      title={`메모·이력 — ${row.title || row.sourcePath || row.rowKey}`}
      wide
      onClose={onClose}
      footer={
        <button type="button" className="button roomy" onClick={onClose}>
          닫기
        </button>
      }
    >
      <div className="note-panel" data-testid="note-panel">
        {lastNote ? (
          <p className="case-help" data-testid="note-current-meta">
            현재 메모: {lastNote.author || "작성자 없음"} ·{" "}
            <time dateTime={lastNote.changed_at}>{formatTimestamp(lastNote.changed_at, timezone)}</time>
          </p>
        ) : null}
        <form
          className="note-panel-form"
          aria-label="메모 저장"
          onSubmit={(event) => {
            event.preventDefault();
            if (!reason) void save();
          }}
        >
          <div className="case-field">
            <label htmlFor={authorId}>작성자</label>
            <input
              id={authorId}
              type="text"
              value={author}
              placeholder={DEFAULT_REVIEWER}
              maxLength={60}
              onChange={(event) => setAuthor(event.target.value)}
            />
          </div>
          <div className="case-field">
            <label htmlFor={noteId}>메모</label>
            <textarea id={noteId} rows={3} value={text} onChange={(event) => setText(event.target.value)} />
          </div>
          {error ? <ErrorText key={error}>메모 저장 실패: {error}</ErrorText> : null}
          <div className="case-actions">
            <ReasonButton type="submit" className="button primary" reason={reason} data-testid="note-save">
              메모 저장
            </ReasonButton>
          </div>
        </form>
        <section aria-labelledby={`${noteId}-history`}>
          <h3 id={`${noteId}-history`} className="note-history-title">
            검토 이력
          </h3>
          {history.isPending ? (
            <p className="case-help">이력을 불러오는 중…</p>
          ) : history.error ? (
            <ErrorText>
              이력을 불러오지 못했습니다. {String((history.error as Error).message ?? history.error)}
            </ErrorText>
          ) : entries.length === 0 ? (
            <p className="case-help">이 행의 검토 기록이 없습니다.</p>
          ) : (
            <ol className="note-history" aria-label={`검토 이력 ${entries.length}건, 최신순`}>
              {entries.map((entry) => (
                <HistoryItem key={entry.version} entry={entry} timezone={timezone} />
              ))}
            </ol>
          )}
        </section>
      </div>
    </Modal>
  );
}
