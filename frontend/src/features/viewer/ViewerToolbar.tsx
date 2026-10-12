/**
 * Viewer actions (visual-polish S5/S6) — one cluster at the right of the viewer header:
 *  - "관련 있음": the one review action kept as a primary toggle (the batch bar owns the rest);
 *  - a status dot: the row's current review status;
 *  - "더보기": 재검토 · 제외 · 보고서 포함 · 북마크 · 메모;
 *  - "⋯" (원본 동작): 원본 열기 · 해시 복사 · 경로 복사 · 인용 복사 · 같은 출처의 다른 행.
 * Every entry is a view of a registered Command (same ids as before), so the palette, the key
 * map and these menus run the same code.
 */

import { useEffect, useRef, useState } from "react";
import { announce, DisabledReason } from "../../a11y";
import { MenuButton, type MenuItem } from "../../components/MenuButton";
import { STATUS_META } from "../../components/StatusChip";
import "../../components/status.css";
import type { Command, CommandContext } from "../../contracts/command";
import { Icon } from "../../icons";
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

interface ViewerToolbarProps {
  sourceCommands: Command[];
  markCommands: Command[];
  ctx: CommandContext;
  onRun: (command: Command) => void;
  /** "같은 출처의 다른 행": its reason when it cannot run, and the action. */
  rowsForSource: { reason?: string; run: () => void };
}

const MARK_PREFIX = "viewer.mark.";
const EXCLUSIVE = ["relevant", "needs-review", "excluded"];

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

export function ViewerToolbar({
  sourceCommands,
  markCommands,
  ctx,
  onRun,
  rowsForSource,
}: ViewerToolbarProps) {
  const target = useViewerTarget();
  const row = useViewerRowContext();
  const [noteOpen, setNoteOpen] = useState(false);
  const [applied, setApplied] = useState<{ key: string; actions: string[]; cleared: string[] }>({
    key: "",
    actions: [],
    cleared: [],
  });
  const moreRef = useRef<HTMLSpanElement>(null);
  const key = target ? noteKey(target.runId, target.ref) : "";
  const noteReason = target ? markDisabledReason(target, "relevant") : "뷰어에 표시된 행이 없습니다.";

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
        const clears = undo === "clear-review" ? EXCLUSIVE : [action];
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
        const kept = EXCLUSIVE.includes(action)
          ? base.actions.filter((a) => !EXCLUSIVE.includes(a))
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
      moreRef.current?.querySelector<HTMLButtonElement>("button")?.focus();
    } catch (error) {
      announce(`메모 저장 실패: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const markOf = (command: Command) => command.id.slice(MARK_PREFIX.length);
  const relevant = markCommands.find((command) => markOf(command) === "relevant");
  const others = markCommands.filter((command) => markOf(command) !== "relevant");
  const relevantReason = relevant?.disabledReason?.(ctx);
  const relevantPressed = isPressed("relevant");

  // The status dot: the current exclusive status, else 보고서 포함 / 북마크, else 미검토.
  const current =
    EXCLUSIVE.find((action) => isPressed(action)) ??
    (isPressed("include-in-report") ? "include-in-report" : isPressed("bookmark") ? "bookmark" : null);
  const currentLabel = current ? STATUS_META[current as keyof typeof STATUS_META].label : "미검토";

  const reviewItems: MenuItem[] = [
    ...others.map((command) => {
      const action = markOf(command);
      return {
        id: command.id,
        label: command.label.replace(/^표시: /, ""),
        command: command.id,
        status: action,
        checked: isPressed(action),
        disabledReason: command.disabledReason?.(ctx),
        onSelect: () => run(command),
      };
    }),
    {
      id: "viewer.note",
      label: "메모…",
      command: "viewer.note",
      separator: true,
      disabledReason: noteReason,
      onSelect: () => setNoteOpen(true),
    },
  ];

  const sourceItems: MenuItem[] = [
    ...sourceCommands.map((command) => ({
      id: command.id,
      label: command.label,
      command: command.id,
      disabledReason: command.disabledReason?.(ctx),
      onSelect: () => run(command),
    })),
    {
      id: "navigate.rows-for-source",
      label: "같은 출처의 다른 행",
      command: "navigate.rows-for-source",
      separator: true,
      disabledReason: rowsForSource.reason,
      onSelect: rowsForSource.run,
    },
  ];

  return (
    <>
      <div className="viewer-actions">
        {relevant ? (
          <DisabledReason reason={relevantReason}>
            <button
              type="button"
              className="viewer-primary"
              data-command={relevant.id}
              data-status-button="relevant"
              aria-pressed={relevantPressed}
              title={
                relevantReason
                  ? undefined
                  : relevantPressed
                    ? "관련 있음 — 다시 누르면 해제합니다"
                    : `${relevant.label}${relevant.shortcut ? ` (${relevant.shortcut})` : ""}`
              }
              onClick={() => run(relevant)}
            >
              {relevantPressed ? <Icon name="check" /> : <Icon name="flag" />}
              <span>관련 있음</span>
            </button>
          </DisabledReason>
        ) : null}
        <span
          className="viewer-status"
          role="img"
          aria-label={`리뷰 상태: ${currentLabel}`}
          title={`리뷰 상태: ${currentLabel}`}
          data-testid="viewer-review-status"
        >
          <span className="status-dot" data-status={current ?? undefined} />
        </span>
        <span ref={moreRef} className="viewer-review-more">
          <MenuButton
            label="리뷰 더보기"
            items={reviewItems}
            triggerClassName="viewer-tool-trigger"
            onDisabled={(reason) => announce(reason)}
            testId="viewer-review-menu"
          >
            <span>더보기</span>
            <Icon name="chevron-down" size={14} />
          </MenuButton>
        </span>
        <MenuButton
          label="원본 동작"
          items={sourceItems}
          triggerClassName="viewer-icon-button"
          onDisabled={(reason) => announce(reason)}
          testId="viewer-source-menu"
        >
          <Icon name="more" />
        </MenuButton>
      </div>
      {noteOpen && target ? (
        <NoteForm onSave={(text) => void saveNote(text)} onCancel={() => setNoteOpen(false)} />
      ) : null}
    </>
  );
}
