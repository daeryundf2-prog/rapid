/**
 * The review-conflict prompt (design review F14): another examiner changed a mark after this
 * console read it, so nothing was saved. It says who, when and to what ("김철수가 14:05 KST에
 * ‘재검토’로 바꿈") and offers [내 판정으로 바꾸기] / [그대로 두기]. An alertdialog: the sentence
 * is its description, focus starts on the safe choice (그대로 두기), Tab stays inside, Esc keeps.
 */

import { type KeyboardEvent, useEffect, useId, useRef, useState } from "react";
import type { ReviewConflict } from "../../api/caseDb";
import { useTimezone } from "../../state/hooks";
import {
  type ConflictChoice,
  type ConflictPrompt,
  conflictSentence,
  useReviewConflict,
} from "./reviewConflict";
import "../case/case.css";
import "./review.css";

const FOCUSABLE = "button:not([disabled])";

export function ReviewConflictDialog({ prompt }: { prompt: ConflictPrompt }) {
  const { timezone } = useTimezone();
  const close = useReviewConflict((s) => s.close);
  const titleId = useId();
  const descriptionId = useId();
  const ref = useRef<HTMLDivElement>(null);
  const keepRef = useRef<HTMLButtonElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const count = prompt.conflicts.length;

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    keepRef.current?.focus();
    return () => previous?.focus?.();
  }, []);

  const choose = async (choice: ConflictChoice) => {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await prompt.resolve(choice);
      // A new conflict (a third change meanwhile) replaced this prompt: leave that one open.
      if (useReviewConflict.getState().prompt === prompt) close();
    } catch (failure) {
      if (useReviewConflict.getState().prompt !== prompt) return;
      setError(failure instanceof Error ? failure.message : String(failure));
      setBusy(false);
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.stopPropagation();
      void choose("keep");
      return;
    }
    if (event.key !== "Tab" || !ref.current) return;
    const items = [...ref.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
    const first = items[0];
    const last = items[items.length - 1];
    if (!first || !last) return;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };

  return (
    <div className="case-modal-backdrop">
      <div
        ref={ref}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        tabIndex={-1}
        className="case-modal review-conflict"
        data-testid="review-conflict"
        onKeyDown={onKeyDown}
      >
        <header className="case-modal-header">
          <h2 id={titleId}>다른 판정이 먼저 저장됨</h2>
        </header>
        <div className="case-modal-body">
          <div id={descriptionId} className="review-conflict-text">
            <p className="review-conflict-sentence">
              {count === 1
                ? `${conflictSentence(prompt.conflicts[0] as ReviewConflict, timezone)}.`
                : `${count}건의 판정이 이 화면을 연 뒤에 바뀌었습니다.`}
            </p>
            <p>내 판정({prompt.action})은 저장하지 않았습니다.</p>
            {prompt.others > 0 ? (
              <p className="review-conflict-note">
                함께 고른 나머지 {prompt.others}건도 아직 저장하지 않았습니다. ‘그대로 두기’를 고르면 그
                {prompt.others}건에만 적용합니다.
              </p>
            ) : null}
          </div>
          {count > 1 ? (
            <ul className="review-conflict-list" aria-label="바뀐 판정">
              {prompt.conflicts.map((conflict, index) => (
                <li key={`${conflict.target_type}:${conflict.target_id}`}>
                  <span className="review-conflict-title">{prompt.titles[index] || conflict.target_id}</span>
                  <span>{conflictSentence(conflict, timezone)}</span>
                </li>
              ))}
            </ul>
          ) : prompt.titles[0] ? (
            <p className="review-conflict-title">{prompt.titles[0]}</p>
          ) : null}
          {error ? (
            <p className="review-conflict-error" role="alert">
              {error}
            </p>
          ) : null}
        </div>
        <footer className="case-modal-footer">
          <button
            type="button"
            className="button primary roomy"
            disabled={busy}
            data-testid="review-conflict-mine"
            onClick={() => void choose("mine")}
          >
            내 판정으로 바꾸기
          </button>
          <button
            ref={keepRef}
            type="button"
            className="button roomy"
            disabled={busy}
            data-testid="review-conflict-keep"
            onClick={() => void choose("keep")}
          >
            그대로 두기
          </button>
        </footer>
      </div>
    </div>
  );
}
