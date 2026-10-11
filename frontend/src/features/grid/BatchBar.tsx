import { useEffect, useRef, useState } from "react";
import { isChipStatus } from "../../components/StatusChip";
import "../../components/status.css";
import type { CommandContext } from "../../contracts/command";
import { getRegisteredCommand } from "./adapter";
import { BATCH_ACTIONS, batchCommandId } from "./gridCommands";
import { formatCount } from "./gridUtils";
import { MARK_LABELS } from "./reviewActions";

export interface BatchBarProps {
  selectedCount: number;
  context: CommandContext;
  onDisabled: (reason: string) => void;
  onClear: () => void;
  /** Applies the typed tag to the selection. */
  onTag: (tag: string) => void;
  tagPromptOpen: boolean;
  onTagPromptChange: (open: boolean) => void;
  /** Applies one note to every selected row (X5). The 메모 button is hidden when absent. */
  onNote?: (note: string) => void;
}

/**
 * Appears while selection > 0. Every button is a `grid.batch.*` Command; the
 * ones that cannot run stay focusable with `aria-disabled` and a reason.
 */
export function BatchBar({
  selectedCount,
  context,
  onDisabled,
  onClear,
  onTag,
  tagPromptOpen: promptOpen,
  onTagPromptChange: setPromptOpen,
  onNote,
}: BatchBarProps) {
  const [tag, setTag] = useState("");
  const [noteOpen, setNoteOpen] = useState(false);
  const [note, setNote] = useState("");
  const noteRef = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    if (noteOpen) noteRef.current?.focus();
  }, [noteOpen]);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (promptOpen) inputRef.current?.focus();
  }, [promptOpen]);

  if (selectedCount === 0) return null;

  return (
    <div className="grid-batch" role="toolbar" aria-label="선택 항목 일괄 처리">
      <strong className="grid-batch-count">선택 {formatCount(selectedCount)}건</strong>
      {BATCH_ACTIONS.map((action) => {
        const command = getRegisteredCommand(batchCommandId(action));
        const reason =
          command?.disabledReason?.(context) ?? (command ? undefined : "명령을 사용할 수 없습니다.");
        return (
          <button
            key={action}
            type="button"
            className="grid-btn"
            data-command={batchCommandId(action)}
            data-status-button={isChipStatus(action) ? action : undefined}
            aria-disabled={reason ? true : undefined}
            title={reason}
            onClick={() => {
              if (reason || !command) {
                onDisabled(reason ?? "명령을 사용할 수 없습니다.");
                return;
              }
              void command.run(context);
            }}
          >
            {MARK_LABELS[action]}
          </button>
        );
      })}
      {promptOpen ? (
        <form
          className="grid-tag-prompt"
          onSubmit={(event) => {
            event.preventDefault();
            const value = tag.trim();
            if (!value) return;
            onTag(value);
            setTag("");
            setPromptOpen(false);
          }}
        >
          <label>
            <span className="sr-only">태그</span>
            <input
              ref={inputRef}
              value={tag}
              placeholder="태그 이름"
              onChange={(event) => setTag(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Escape") {
                  event.preventDefault();
                  setPromptOpen(false);
                }
              }}
            />
          </label>
          <button type="submit" className="grid-btn">
            적용
          </button>
        </form>
      ) : null}
      {onNote ? (
        <button
          type="button"
          className="grid-btn"
          data-command="grid.batch.note"
          aria-expanded={noteOpen}
          onClick={() => setNoteOpen((open) => !open)}
        >
          메모
        </button>
      ) : null}
      {noteOpen && onNote ? (
        <form
          className="note-form"
          aria-label="일괄 메모"
          onSubmit={(event) => {
            event.preventDefault();
            const value = note.trim();
            if (!value) return;
            onNote(value);
            setNote("");
            setNoteOpen(false);
          }}
        >
          <label>
            <span className="sr-only">메모 (선택 {selectedCount}건에 동일 적용)</span>
            <textarea
              ref={noteRef}
              value={note}
              placeholder={`선택한 ${selectedCount}건에 같은 메모를 저장`}
              onChange={(event) => setNote(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Escape") {
                  event.preventDefault();
                  setNoteOpen(false);
                }
              }}
            />
          </label>
          <div className="note-form-actions">
            <button type="submit" className="grid-btn" disabled={!note.trim()}>
              저장
            </button>
            <button type="button" className="grid-btn" onClick={() => setNoteOpen(false)}>
              취소
            </button>
          </div>
        </form>
      ) : null}
      <button type="button" className="grid-btn grid-btn-quiet" onClick={onClear}>
        선택 해제
      </button>
    </div>
  );
}
