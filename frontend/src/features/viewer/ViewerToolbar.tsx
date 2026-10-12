import { type KeyboardEvent, useEffect, useRef, useState } from "react";
import { announce, DisabledReason } from "../../a11y";
import { isChipStatus } from "../../components/StatusChip";
import "../../components/status.css";
import type { Command, CommandContext } from "../../contracts/command";
import {
  applyNote,
  applyReviewAction,
  MARK_LABELS,
  storeNotice,
  unmarkActionOf,
} from "../grid/reviewActions";
import { noteKey, setSessionNote } from "../grid/sessionNotes";
import { useViewerRowContext, useViewerTarget } from "./adapter";
import { markDisabledReason, targetAsGridRow } from "./citation";

interface ToolbarButtonProps {
  command: Command;
  ctx: CommandContext;
  label?: string;
  tabStop?: boolean;
  /** Review status this button sets; pressed = already applied (filled with the status colour). */
  status?: string;
  pressed?: boolean;
  onRun: (command: Command) => void;
}

function ToolbarButton({ command, ctx, label, tabStop, status, pressed, onRun }: ToolbarButtonProps) {
  const reason = command.disabledReason?.(ctx);
  const text = label ?? command.label;
  return (
    <DisabledReason reason={reason}>
      <button
        type="button"
        className="viewer-tool"
        data-command={command.id}
        data-status-button={status}
        aria-pressed={status ? Boolean(pressed) : undefined}
        title={
          reason
            ? undefined
            : pressed && status && status !== "bookmark"
              ? `${command.label} — 다시 누르면 해제합니다`
              : command.shortcut
                ? `${command.label} (${command.shortcut})`
                : command.label
        }
        tabIndex={tabStop ? 0 : -1}
        onClick={() => onRun(command)}
      >
        {text}
      </button>
    </DisabledReason>
  );
}

interface ViewerToolbarProps {
  sourceCommands: Command[];
  markCommands: Command[];
  ctx: CommandContext;
  onRun: (command: Command) => void;
}

const MARK_PREFIX = "viewer.mark.";

/** Inline 메모 form: textarea + 저장/취소, Esc cancels. */
function NoteForm({ onSave, onCancel }: { onSave: (text: string) => void; onCancel: () => void }) {
  const [text, setText] = useState("");
  const ref = useRef<HTMLTextAreaElement>(null);
  useEffect(() => ref.current?.focus(), []);
  return (
    <form
      className="note-form"
      aria-label="메모 입력"
      onSubmit={(event) => {
        event.preventDefault();
        if (text.trim()) onSave(text);
      }}
    >
      <label>
        <span className="sr-only">메모</span>
        <textarea
          ref={ref}
          value={text}
          placeholder="이 항목에 대한 메모"
          onChange={(event) => setText(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Escape") {
              event.preventDefault();
              event.stopPropagation();
              onCancel();
            }
          }}
        />
      </label>
      <div className="note-form-actions">
        <button type="submit" className="viewer-button" disabled={!text.trim()}>
          저장
        </button>
        <button type="button" className="viewer-button" onClick={onCancel}>
          취소
        </button>
      </div>
    </form>
  );
}

/** role=toolbar with one tab stop (the first button); ←/→/Home/End move between buttons. */
export function ViewerToolbar({ sourceCommands, markCommands, ctx, onRun }: ViewerToolbarProps) {
  const ref = useRef<HTMLDivElement>(null);
  const target = useViewerTarget();
  const row = useViewerRowContext();
  const [noteOpen, setNoteOpen] = useState(false);
  const [applied, setApplied] = useState<{ key: string; actions: string[]; cleared: string[] }>({
    key: "",
    actions: [],
    cleared: [],
  });
  const key = target ? noteKey(target.runId, target.ref) : "";
  const noteReason = target ? markDisabledReason(target, "relevant") : "뷰어에 표시된 행이 없습니다.";
  const buttons = () =>
    Array.from(ref.current?.querySelectorAll<HTMLButtonElement>("button.viewer-tool") ?? []);

  // A different row closes the form.
  // biome-ignore lint/correctness/useExhaustiveDependencies: close on target change only
  useEffect(() => setNoteOpen(false), [key]);

  const isPressed = (action: string): boolean => {
    if (applied.key === key && applied.actions.includes(action)) return true;
    if (applied.key === key && applied.cleared.includes(action)) return false;
    if (!row) return false;
    if (action === "bookmark") return row.tags.includes("북마크");
    if (action === "include-in-report") {
      return row.fields.includeInReport === true || row.reviewStatus === "include-in-report";
    }
    return row.reviewStatus === action;
  };

  /** A pressed review toggle un-presses: status back to `unreviewed` / out of the report. */
  const unmark = async (action: string) => {
    const undo = unmarkActionOf(action);
    if (!target || !undo) return;
    try {
      const result = await applyReviewAction(target.runId, [targetAsGridRow(target)], undo);
      setApplied((prev) => {
        const base = prev.key === key ? prev : { actions: [], cleared: [] };
        const exclusive = ["relevant", "needs-review", "excluded"];
        const clears = undo === "clear-review" ? exclusive : [action];
        return {
          key,
          actions: base.actions.filter((a) => !clears.includes(a)),
          cleared: [...base.cleared.filter((a) => !clears.includes(a)), ...clears],
        };
      });
      announce(`표시 해제됨: ${MARK_LABELS[undo]}${storeNotice(result)}`);
    } catch (error) {
      announce(`표시 해제 실패: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const run = (command: Command) => {
    const markAction = command.id.startsWith(MARK_PREFIX) ? command.id.slice(MARK_PREFIX.length) : "";
    if (markAction && !command.disabledReason?.(ctx) && unmarkActionOf(markAction) && isPressed(markAction)) {
      void unmark(markAction);
      return;
    }
    onRun(command);
    if (markAction && !command.disabledReason?.(ctx)) {
      const action = markAction;
      setApplied((prev) => {
        const base = prev.key === key ? prev : { actions: [], cleared: [] };
        // Review statuses are exclusive; bookmark / include-in-report accumulate.
        const exclusive = ["relevant", "needs-review", "excluded"];
        const kept = exclusive.includes(action)
          ? base.actions.filter((a) => !exclusive.includes(a))
          : base.actions;
        return {
          key,
          actions: [...kept.filter((a) => a !== action), action],
          cleared: base.cleared.filter((a) => a !== action),
        };
      });
    }
  };

  const saveNote = async (text: string) => {
    if (!target) return;
    try {
      const result = await applyNote(target.runId, [targetAsGridRow(target)], text);
      setSessionNote(key, text.trim());
      setNoteOpen(false);
      announce(`메모를 저장했습니다.${storeNotice(result)}`);
      ref.current?.querySelector<HTMLButtonElement>('[data-command="viewer.note"]')?.focus();
    } catch (error) {
      announce(`메모 저장 실패: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.altKey) return;
    const list = buttons();
    const index = list.indexOf(document.activeElement as HTMLButtonElement);
    let next = -1;
    if (event.key === "ArrowRight") next = index + 1;
    else if (event.key === "ArrowLeft") next = index - 1;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = list.length - 1;
    else return;
    event.preventDefault();
    const target = list[(next + list.length) % list.length];
    target?.focus();
  };

  return (
    <>
      <div ref={ref} className="viewer-toolbar" role="toolbar" aria-label="원본 동작" onKeyDown={onKeyDown}>
        <div className="viewer-tool-group">
          {sourceCommands.map((command, index) => (
            <ToolbarButton key={command.id} command={command} ctx={ctx} tabStop={index === 0} onRun={run} />
          ))}
        </div>
        <div className="viewer-tool-group">
          {markCommands.map((command) => {
            const action = command.id.startsWith(MARK_PREFIX) ? command.id.slice(MARK_PREFIX.length) : "";
            const status = action === "bookmark" || isChipStatus(action) ? action : undefined;
            return (
              <ToolbarButton
                key={command.id}
                command={command}
                ctx={ctx}
                label={command.label.replace(/^표시: /, "")}
                status={status}
                pressed={status ? isPressed(status) : false}
                onRun={run}
              />
            );
          })}
          <DisabledReason reason={noteReason}>
            <button
              type="button"
              className="viewer-tool"
              data-command="viewer.note"
              aria-expanded={noteOpen}
              tabIndex={-1}
              onClick={() => setNoteOpen((open) => !open)}
            >
              메모
            </button>
          </DisabledReason>
        </div>
      </div>
      {noteOpen && target ? (
        <NoteForm onSave={(text) => void saveNote(text)} onCancel={() => setNoteOpen(false)} />
      ) : null}
    </>
  );
}
