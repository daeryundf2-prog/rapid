import { useEffect, useRef, useState } from "react";
import { isChipStatus } from "../../components/StatusChip";
import "../../components/status.css";
import { MenuButton, type MenuItem } from "../../components/MenuButton";
import type { CommandContext } from "../../contracts/command";
import { Icon } from "../../icons";
import { getRegisteredCommand } from "./adapter";
import { BATCH_ACTIONS, batchCommandId, OCR_SELECTED_COMMAND } from "./gridCommands";
import { formatCount } from "./gridUtils";
import type { BatchAction } from "./reviewActions";
import { MARK_LABELS } from "./reviewActions";

/** A single selected row is served by the viewer and the row menu; the bar is for two or more. */
export const BATCH_BAR_MIN = 2;

/** Review marks (left group) and the tools behind the divider (folded into ⋯ when narrow). */
const REVIEW_ACTIONS = BATCH_ACTIONS.filter((a) => a !== "tag" && a !== "extract");
const TOOL_ACTIONS: BatchAction[] = ["tag", "extract"];

/** Bar wording (review #2): the primary mark reads "관련 있음" like the status chip it sets. */
const BAR_LABELS: Partial<Record<BatchAction, string>> = { relevant: "관련 있음" };

export interface BatchBarState {
  visible: boolean;
  /** Selected rows (the actions apply to all of them). */
  count: number;
}

/**
 * When the floating bar shows (review #2): two or more rows selected, at least one of them still
 * in the rows on screen (a filter that hides the whole selection hides the bar). An open tag
 * prompt (T on one row) keeps it up, since the prompt lives inside the bar.
 */
export function batchBarState(
  selected: ReadonlySet<string>,
  present: (key: string) => boolean,
  promptOpen = false,
): BatchBarState {
  const count = selected.size;
  if (count === 0) return { visible: false, count };
  let onScreen = false;
  for (const key of selected) {
    if (present(key)) {
      onScreen = true;
      break;
    }
  }
  if (!onScreen) return { visible: false, count };
  return { visible: count >= BATCH_BAR_MIN || promptOpen, count };
}

export interface BatchBarProps {
  selectedCount: number;
  /** batchBarState(): false hides the bar (one row, or the selection is filtered away). */
  visible: boolean;
  context: CommandContext;
  onDisabled: (reason: string) => void;
  onClear: () => void;
  /** Applies the typed tag to the selection. */
  onTag: (tag: string) => void;
  tagPromptOpen: boolean;
  onTagPromptChange: (open: boolean) => void;
  /** Applies one note to every selected row (X5). The 메모 button is hidden when absent. */
  onNote?: (note: string) => void;
  /**
   * Reports the bar's rendered height (0 when hidden): it grows with the tag / note editors,
   * and the grid reserves at least that much room under its last row (review B2-7).
   */
  onHeight?: (px: number) => void;
}

/**
 * Appears while two or more rows are selected — the one place batch review actions live
 * (visual-polish S6, review #2). It floats over the bottom of the grid, so its appearance never
 * shifts the rows. Every button is a `grid.batch.*` Command; the ones that cannot run stay
 * focusable with `aria-disabled` and a reason. One row: nowrap; below 900px the tools
 * (태그 · 추출 · OCR · 메모) fold into a ⋯ menu.
 */
export function BatchBar({
  selectedCount,
  visible,
  context,
  onDisabled,
  onClear,
  onTag,
  tagPromptOpen: promptOpen,
  onTagPromptChange: setPromptOpen,
  onNote,
  onHeight,
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

  const barRef = useRef<HTMLDivElement>(null);
  const heightRef = useRef(onHeight);
  heightRef.current = onHeight;
  useEffect(() => {
    const el = barRef.current;
    if (!visible || !el) {
      heightRef.current?.(0);
      return;
    }
    const report = () => heightRef.current?.(el.offsetHeight);
    report();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(report);
    observer.observe(el);
    return () => observer.disconnect();
  }, [visible]);

  if (!visible) return null;

  const reasonOf = (id: string) => {
    const command = getRegisteredCommand(id);
    return {
      command,
      reason: command?.disabledReason?.(context) ?? (command ? undefined : "명령을 사용할 수 없습니다."),
    };
  };
  const runCommand = (id: string) => {
    const { command, reason } = reasonOf(id);
    if (reason || !command) {
      onDisabled(reason ?? "명령을 사용할 수 없습니다.");
      return;
    }
    void command.run(context);
  };
  const actionButton = (action: BatchAction) => {
    const id = batchCommandId(action);
    const { reason } = reasonOf(id);
    return (
      <button
        key={action}
        type="button"
        className={action === "relevant" ? "button primary" : "button ghost"}
        data-command={id}
        data-status-button={isChipStatus(action) ? action : undefined}
        aria-disabled={reason ? true : undefined}
        title={reason}
        onClick={() => runCommand(id)}
      >
        {BAR_LABELS[action] ?? MARK_LABELS[action]}
      </button>
    );
  };
  const ocr = getRegisteredCommand(OCR_SELECTED_COMMAND);
  const ocrReason = ocr?.disabledReason?.(context);

  // The same tools as menu items for the narrow layout (the inline group is hidden by CSS there).
  const toolItems: MenuItem[] = [
    ...TOOL_ACTIONS.map((action) => ({
      id: action,
      label: MARK_LABELS[action],
      command: batchCommandId(action),
      icon: action === "tag" ? ("tag" as const) : ("download" as const),
      disabledReason: reasonOf(batchCommandId(action)).reason,
      onSelect: () => runCommand(batchCommandId(action)),
    })),
    ...(ocr
      ? [
          {
            id: "ocr",
            label: ocr.label,
            command: OCR_SELECTED_COMMAND,
            icon: "eye" as const,
            disabledReason: ocrReason,
            onSelect: () => runCommand(OCR_SELECTED_COMMAND),
          },
        ]
      : []),
    ...(onNote
      ? [{ id: "note", label: "메모…", icon: "message" as const, onSelect: () => setNoteOpen(true) }]
      : []),
  ];

  return (
    <div ref={barRef} className="grid-batch" role="toolbar" aria-label="선택 항목 일괄 처리">
      <div className="grid-batch-row">
        <strong className="grid-batch-count">선택 {formatCount(selectedCount)}건</strong>
        <div className="grid-batch-group">{REVIEW_ACTIONS.map(actionButton)}</div>
        <span className="grid-batch-divider" aria-hidden="true" />
        <div className="grid-batch-group grid-batch-tools">
          {TOOL_ACTIONS.map(actionButton)}
          {ocr ? (
            <button
              type="button"
              className="button ghost"
              data-command={OCR_SELECTED_COMMAND}
              aria-disabled={ocrReason ? true : undefined}
              title={ocrReason}
              onClick={() => runCommand(OCR_SELECTED_COMMAND)}
            >
              {ocr.label}
            </button>
          ) : null}
          {onNote ? (
            <button
              type="button"
              className="button ghost"
              data-command="grid.batch.note"
              aria-expanded={noteOpen}
              onClick={() => setNoteOpen((open) => !open)}
            >
              메모
            </button>
          ) : null}
        </div>
        <span className="grid-batch-more">
          <MenuButton label="도구 더보기" items={toolItems} align="end" onDisabled={onDisabled}>
            <Icon name="more" />
          </MenuButton>
        </span>
        <button type="button" className="button ghost grid-batch-clear" onClick={onClear}>
          <Icon name="close" />
          <span>선택 해제</span>
        </button>
      </div>
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
          <button type="submit" className="button">
            적용
          </button>
        </form>
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
            <button type="submit" className="button primary" disabled={!note.trim()}>
              저장
            </button>
            <button type="button" className="button ghost" onClick={() => setNoteOpen(false)}>
              취소
            </button>
          </div>
        </form>
      ) : null}
    </div>
  );
}
