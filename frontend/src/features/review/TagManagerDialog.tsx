/**
 * 태그 관리 (AXIOM E3, plan §3.3): the case's review tags — name, one of the eight colour
 * tokens, a digit key 1–9 and a description — with their mark counts and author. Create,
 * edit and (soft) delete; system tags (북마크 · 우선순위 1–5) keep their name. The dialog is the
 * shared Modal: labelled, Esc closes, Tab trapped, focus returns to the opener. Errors are a
 * visible line + one assertive sentence (ErrorText); results go through the polite announcer.
 */

import { useId, useState } from "react";
import { announce } from "../../a11y";
import { type CaseTag, TAG_COLOR_LABELS, TAG_COLOR_TOKENS, type TagColorToken } from "../../api/reviewTools";
import { ErrorText } from "../case/ErrorText";
import { Modal } from "../case/Modal";
import { ReasonButton } from "../case/ReasonButton";
import { currentReviewer, setReviewer } from "./author";
import { removeTag, saveNewTag, saveTagChanges, sortTags, useCaseTags } from "./tagStore";
import "./review.css";

const DIGITS = [1, 2, 3, 4, 5, 6, 7, 8, 9] as const;
export const SYSTEM_TAG_REASON = "기본 태그는 이름을 바꾸거나 삭제할 수 없습니다";

interface Draft {
  id: number | null;
  name: string;
  color: TagColorToken;
  shortcut: number | null;
  description: string;
  system: boolean;
}

const EMPTY_DRAFT: Draft = {
  id: null,
  name: "",
  color: "tag-5",
  shortcut: null,
  description: "",
  system: false,
};

/** Why the draft cannot be saved (Korean), or undefined. */
export function draftReason(draft: Draft, tags: readonly CaseTag[]): string | undefined {
  const name = draft.name.replace(/\s+/g, " ").trim();
  if (!name) return "태그 이름을 입력하세요";
  if (name.length > 60) return "태그 이름은 60자 이하여야 합니다";
  const clash = tags.find(
    (tag) => tag.id !== draft.id && tag.name.toLocaleLowerCase() === name.toLocaleLowerCase(),
  );
  if (clash) return `같은 이름의 태그가 이미 있습니다: ${clash.name}`;
  if (draft.shortcut !== null) {
    const owner = tags.find((tag) => tag.id !== draft.id && tag.shortcut === draft.shortcut);
    if (owner) return `단축키 ${draft.shortcut}은(는) 이미 '${owner.name}' 태그에 지정되어 있습니다`;
  }
  if (draft.description.length > 500) return "설명은 500자 이하여야 합니다";
  return undefined;
}

function Swatch({ token }: { token: string }) {
  return <span className="tag-swatch" style={{ background: `var(--${token})` }} aria-hidden="true" />;
}

export function TagManagerDialog({ runId, onClose }: { runId: string; onClose: () => void }) {
  const state = useCaseTags(runId);
  const tags = sortTags(state.tags);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<CaseTag | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [author, setAuthor] = useState(() => (currentReviewer() === "web-ui" ? "" : currentReviewer()));
  const formId = useId();
  const nameId = useId();
  const shortcutId = useId();
  const descriptionId = useId();
  const authorId = useId();

  const startEdit = (tag: CaseTag | null) => {
    setError(null);
    setConfirmDelete(null);
    setDraft(
      tag
        ? {
            id: tag.id,
            name: tag.name,
            color: tag.color_token,
            shortcut: tag.shortcut,
            description: tag.description,
            system: tag.kind === "system",
          }
        : { ...EMPTY_DRAFT },
    );
  };

  const run = async (work: () => Promise<string>) => {
    setBusy(true);
    setError(null);
    try {
      announce(await work());
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
    } finally {
      setBusy(false);
    }
  };

  const save = () => {
    if (!draft) return;
    const input = {
      name: draft.name.replace(/\s+/g, " ").trim(),
      color_token: draft.color,
      shortcut: draft.shortcut,
      description: draft.description.trim(),
    };
    void run(async () => {
      if (draft.id === null) {
        const tag = await saveNewTag(runId, input);
        setDraft(null);
        return `태그 '${tag.name}'을(를) 만들었습니다`;
      }
      const { name, ...rest } = input;
      const tag = await saveTagChanges(runId, draft.id, draft.system ? rest : { name, ...rest });
      setDraft(null);
      return `태그 '${tag.name}'을(를) 저장했습니다`;
    });
  };

  const remove = (tag: CaseTag) => {
    void run(async () => {
      const removed = await removeTag(runId, tag.id);
      setConfirmDelete(null);
      return `태그 '${tag.name}'을(를) 삭제했습니다. ${removed.toLocaleString("ko-KR")}개 행에서 뺐습니다`;
    });
  };

  const saveReason = draft
    ? (draftReason(draft, tags) ?? (busy ? "저장하는 중입니다" : undefined))
    : undefined;
  const takenBy = (digit: number) => tags.find((tag) => tag.shortcut === digit && tag.id !== draft?.id);

  return (
    <Modal
      title="태그 관리"
      wide
      onClose={onClose}
      footer={
        <button type="button" className="button roomy" onClick={onClose}>
          닫기
        </button>
      }
    >
      <div className="tag-manager" data-testid="tag-manager">
        <div className="case-field">
          <label htmlFor={authorId}>작성자 (태그·메모에 기록)</label>
          <input
            id={authorId}
            type="text"
            value={author}
            placeholder="web-ui"
            maxLength={60}
            onChange={(event) => setAuthor(event.target.value)}
            onBlur={() => setReviewer(author)}
          />
        </div>
        {error ? <ErrorText key={error}>{error}</ErrorText> : null}
        {state.status === "loading" && tags.length === 0 ? (
          <p className="case-help">태그를 불러오는 중…</p>
        ) : state.status === "error" ? (
          <ErrorText>태그를 불러오지 못했습니다. {state.error}</ErrorText>
        ) : !state.exists ? (
          <p className="case-help">
            이 런에는 아직 케이스 DB가 없습니다. 새 태그를 만들면 케이스 DB를 준비한 뒤 저장합니다.
          </p>
        ) : null}
        <table className="tag-table" aria-label="케이스 태그">
          <thead>
            <tr>
              <th scope="col">이름</th>
              <th scope="col">단축키</th>
              <th scope="col">행</th>
              <th scope="col">설명</th>
              <th scope="col">작성자</th>
              <th scope="col">
                <span className="sr-only">동작</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {tags.map((tag) => (
              <tr key={tag.id} data-testid="tag-row">
                <th scope="row">
                  <span className="tag-name">
                    <Swatch token={tag.color_token} />
                    <span>{tag.name}</span>
                    <span className="sr-only">, {TAG_COLOR_LABELS[tag.color_token] ?? tag.color_token}</span>
                    {tag.kind === "system" ? <span className="badge muted">기본</span> : null}
                  </span>
                </th>
                <td>{tag.shortcut ?? "—"}</td>
                <td className="num">{tag.count.toLocaleString("ko-KR")}</td>
                <td className="tag-desc">{tag.description || "—"}</td>
                <td>{tag.created_by || "—"}</td>
                <td className="tag-actions">
                  <button
                    type="button"
                    className="button ghost"
                    aria-label={`${tag.name} 태그 편집`}
                    onClick={() => startEdit(tag)}
                  >
                    편집
                  </button>
                  <ReasonButton
                    className="button ghost"
                    aria-label={`${tag.name} 태그 삭제`}
                    reason={tag.kind === "system" ? SYSTEM_TAG_REASON : undefined}
                    onClick={() => {
                      setDraft(null);
                      setConfirmDelete(tag);
                    }}
                  >
                    삭제
                  </ReasonButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {confirmDelete ? (
          <fieldset className="tag-confirm">
            <legend className="sr-only">태그 삭제 확인</legend>
            <p>
              '{confirmDelete.name}' 태그를 삭제할까요? 이 태그가 붙은{" "}
              {confirmDelete.count.toLocaleString("ko-KR")}개 행에서 빠집니다. 태그 기록은 삭제 표시로
              남습니다.
            </p>
            <div className="case-actions">
              <button type="button" className="button" onClick={() => setConfirmDelete(null)}>
                취소
              </button>
              <ReasonButton
                className="button primary"
                reason={busy ? "처리하는 중입니다" : undefined}
                onClick={() => remove(confirmDelete)}
              >
                삭제
              </ReasonButton>
            </div>
          </fieldset>
        ) : null}
        {draft ? (
          <form
            id={formId}
            className="tag-form"
            aria-label={draft.id === null ? "새 태그" : `${draft.name} 태그 편집`}
            onSubmit={(event) => {
              event.preventDefault();
              if (!saveReason) save();
            }}
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                // Close the form, not the dialog.
                event.stopPropagation();
                setDraft(null);
              }
            }}
          >
            <div className="case-field">
              <label htmlFor={nameId}>이름</label>
              <input
                id={nameId}
                type="text"
                value={draft.name}
                maxLength={60}
                readOnly={draft.system}
                aria-describedby={draft.system ? `${nameId}-help` : undefined}
                onChange={(event) => setDraft({ ...draft, name: event.target.value })}
              />
              {draft.system ? (
                <p id={`${nameId}-help`} className="case-help">
                  {SYSTEM_TAG_REASON}
                </p>
              ) : null}
            </div>
            <fieldset className="case-field">
              <legend>색</legend>
              <div className="case-radio-group">
                {TAG_COLOR_TOKENS.map((token) => (
                  <label key={token} className="case-option">
                    <input
                      type="radio"
                      name={`${formId}-color`}
                      value={token}
                      checked={draft.color === token}
                      onChange={() => setDraft({ ...draft, color: token })}
                    />
                    <Swatch token={token} />
                    {TAG_COLOR_LABELS[token]}
                  </label>
                ))}
              </div>
            </fieldset>
            <div className="case-field">
              <label htmlFor={shortcutId}>단축키</label>
              <select
                id={shortcutId}
                value={draft.shortcut ?? ""}
                onChange={(event) =>
                  setDraft({ ...draft, shortcut: event.target.value ? Number(event.target.value) : null })
                }
              >
                <option value="">없음</option>
                {DIGITS.map((digit) => {
                  const owner = takenBy(digit);
                  return (
                    <option key={digit} value={digit} disabled={Boolean(owner)}>
                      {digit}
                      {owner ? ` ('${owner.name}'에 지정됨)` : ""}
                    </option>
                  );
                })}
              </select>
              <p className="case-help">탐색·검토 단계에서 행을 고르고 숫자 키를 누르면 이 태그가 붙습니다.</p>
            </div>
            <div className="case-field">
              <label htmlFor={descriptionId}>설명</label>
              <textarea
                id={descriptionId}
                value={draft.description}
                maxLength={500}
                rows={2}
                onChange={(event) => setDraft({ ...draft, description: event.target.value })}
              />
            </div>
            <div className="case-actions">
              <button type="button" className="button" onClick={() => setDraft(null)}>
                취소
              </button>
              <ReasonButton
                type="submit"
                className="button primary"
                reason={saveReason}
                data-testid="tag-save"
              >
                {draft.id === null ? "태그 만들기" : "저장"}
              </ReasonButton>
            </div>
          </form>
        ) : (
          <div className="case-actions">
            <button
              type="button"
              className="button primary"
              onClick={() => startEdit(null)}
              data-testid="tag-new"
            >
              새 태그
            </button>
          </div>
        )}
      </div>
    </Modal>
  );
}
