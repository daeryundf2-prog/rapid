/**
 * Viewer actions (visual-polish S5/S6, review #6; r7 L4 C-W8/C-W9) — one cluster at the right of
 * the viewer header:
 *  - ONE review-status chip "미검토 ▾" (dot + text): its menu sets 관련 · 재검토 · 제외 · 보고서 포함 ·
 *    북마크 (a checked status un-presses);
 *  - one "⋯" menu (더보기): 리뷰 (메모 · 메모 기록 · 태그 관리) · 태그 전파 (one entry, plus one per
 *    tag only when that differs) · 원본 (원본 열기 · 해시/경로/인용 복사 · 같은 출처의 다른 행) · 피벗.
 * Every entry is a view of a registered Command (same ids as before), so the palette, the key
 * map and this menu run the same code; key hints come from the registry.
 */

import { useEffect, useRef, useState } from "react";
import { announce } from "../../a11y";
import { getCommand, runCommand } from "../../commands/registry";
import { MenuButton, type MenuItem } from "../../components/MenuButton";
import { STATUS_META } from "../../components/StatusChip";
import "../../components/status.css";
import type { GridRow } from "../../contracts/collection";
import type { Command, CommandContext } from "../../contracts/command";
import { Icon, isIconName } from "../../icons";
import { useRoute } from "../../state/hooks";
import {
  applyNote,
  applyReviewAction,
  MARK_LABELS,
  storeNotice,
  unmarkActionOf,
} from "../grid/reviewActions";
import { noteKey, setSessionNote } from "../grid/sessionNotes";
import { NOTE_PANEL_COMMAND, TAG_MANAGER_COMMAND } from "../review/commands";
import {
  defaultPropagationTags,
  isSystemTagName,
  PROPAGATE_COMMAND,
  propagateReason,
  runPropagation,
} from "../review/gridTools";
import { useViewerRowContext, useViewerTarget } from "./adapter";
import { markDisabledReason, targetAsGridRow } from "./citation";
import { writeClipboard } from "./commands";
import { layoutFields } from "./fieldSheets";
import { type PivotId, recordPivots } from "./pivots";

/** Menu icons of the pivots. */
const PIVOT_ICONS: Record<PivotId, MenuItem["icon"]> = {
  "same-user": "filter",
  "same-logon": "filter",
  "same-hash": "filter",
  "same-target": "filter",
  "same-key": "filter",
  "same-source": "filter",
  "timeline-window": "clock",
  "matched-event": "external",
  "source-artifact": "external",
};

interface ViewerToolbarProps {
  sourceCommands: Command[];
  markCommands: Command[];
  ctx: CommandContext;
  onRun: (command: Command) => void;
  /** "같은 출처의 다른 행": its reason when it cannot run, and the action. */
  rowsForSource: { reason?: string; run: () => void };
}

const MARK_PREFIX = "viewer.mark.";
/** A shell command that is not registered in this window (the pop-out viewer). */
export const POPOUT_ONLY_REASON = "이 창에서는 쓸 수 없습니다. 메인 창의 뷰어에서 실행하세요";

/**
 * "태그 전파" section of the viewer menu (AXIOM E3), always on the viewer row: the default entry
 * spreads every user tag of the row; one entry per tag follows only where it differs from that
 * default (system tags 북마크 · 우선순위 n spread only this way; one user tag = the default itself,
 * so it is not listed twice — C-W8).
 */
export function propagationItems(row: GridRow | null, runId: string | null): MenuItem[] {
  const rows = row ? [row] : [];
  const user = defaultPropagationTags(rows);
  const all: MenuItem = {
    id: PROPAGATE_COMMAND,
    label: user.length ? `같은 해시 행에 태그 전파 (${user.join(", ")})` : "같은 해시 행에 태그 전파",
    command: PROPAGATE_COMMAND,
    icon: "tag",
    section: "태그 전파",
    disabledReason: propagateReason(runId, rows),
    onSelect: () => void runPropagation(runId, rows),
  };
  const each = (row?.tags ?? [])
    .filter((name) => !(user.length === 1 && user[0] === name))
    .map(
      (name): MenuItem => ({
        id: `${PROPAGATE_COMMAND}.${name}`,
        label: `'${name}'만 전파${isSystemTagName(name) ? " (시스템 태그)" : ""}`,
        command: `${PROPAGATE_COMMAND}.one`,
        icon: "tag",
        disabledReason: propagateReason(runId, rows, [name]),
        onSelect: () => void runPropagation(runId, rows, [name]),
      }),
    );
  return [all, ...each];
}
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
        <button type="submit" className="button primary" disabled={!text.trim()}>
          저장
        </button>
        <button type="button" className="button ghost" onClick={onCancel}>
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
  const { route, navigate } = useRoute();
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

  // The status chip: the current exclusive status, else 보고서 포함 / 북마크, else 미검토.
  const current =
    EXCLUSIVE.find((action) => isPressed(action)) ??
    (isPressed("include-in-report") ? "include-in-report" : isPressed("bookmark") ? "bookmark" : null);
  const currentLabel = current ? STATUS_META[current as keyof typeof STATUS_META].label : "미검토";

  /** The key that marks the row (R / X / I / B): the viewer command's own, else the shell's review.mark.*. */
  const markShortcut = (command: Command, action: string) =>
    command.shortcut ?? getCommand(`review.mark.${action}`)?.shortcut;

  // The one review-status menu (C-W9): every mark, the pressed ones checked (select again = clear).
  const statusItems: MenuItem[] = markCommands.map((command) => {
    const action = markOf(command);
    const pressed = isPressed(action);
    return {
      id: command.id,
      label: `${command.label.replace(/^표시: /, "")}${pressed && unmarkActionOf(action) ? " (해제)" : ""}`,
      command: command.id,
      status: action,
      checked: pressed,
      shortcut: markShortcut(command, action),
      disabledReason: command.disabledReason?.(ctx),
      onSelect: () => run(command),
    };
  });

  const reviewItems: MenuItem[] = [
    {
      id: "viewer.note",
      label: "메모…",
      command: "viewer.note",
      icon: "message",
      section: "리뷰",
      disabledReason: noteReason,
      onSelect: () => setNoteOpen(true),
    },
    // Review tools (AXIOM E3): note history with author/time, tag manager.
    ...[NOTE_PANEL_COMMAND, TAG_MANAGER_COMMAND].map((id): MenuItem => {
      const command = getCommand(id);
      return {
        id,
        label: command?.label ?? id,
        command: id,
        icon: id === NOTE_PANEL_COMMAND ? "clock" : "tag",
        disabledReason: command ? command.disabledReason?.(ctx) : POPOUT_ONLY_REASON,
        onSelect: () => void runCommand(id),
      };
    }),
    ...propagationItems(target ? (row ?? targetAsGridRow(target)) : null, target?.runId ?? null),
  ];

  const sourceItems: MenuItem[] = [
    ...sourceCommands.map((command, index) => ({
      id: command.id,
      label: command.label,
      command: command.id,
      icon: isIconName(command.icon) ? command.icon : undefined,
      shortcut: command.shortcut,
      disabledReason: command.disabledReason?.(ctx),
      section: index === 0 ? "원본" : undefined,
      onSelect: () => run(command),
    })),
    {
      id: "navigate.rows-for-source",
      label: "같은 출처의 다른 행",
      command: "navigate.rows-for-source",
      icon: "list",
      disabledReason: rowsForSource.reason,
      onSelect: rowsForSource.run,
    },
  ];

  // Pivots (viewer redesign §5): the same list as the grid row menu, each with its reason.
  const pivotItems: MenuItem[] = recordPivots(target ? row : null, target?.runId ?? "", route.tz).map(
    (pivot, index) => ({
      id: `viewer.pivot.${pivot.id}`,
      label: pivot.value
        ? `${pivot.label}: ${pivot.value.length > 40 ? `${pivot.value.slice(0, 39)}…` : pivot.value}`
        : pivot.label,
      command: `viewer.pivot.${pivot.id}`,
      icon: PIVOT_ICONS[pivot.id],
      disabledReason: pivot.reason,
      section: index === 0 ? "피벗" : undefined,
      onSelect: () => {
        if (pivot.route) navigate(pivot.route);
      },
    }),
  );
  const copyJsonItem: MenuItem = {
    id: "viewer.copyRecordJson",
    label: "레코드 JSON 복사",
    command: "viewer.copyRecordJson",
    icon: "copy",
    disabledReason: row ? undefined : "뷰어에 표시된 레코드가 없습니다.",
    onSelect: () => {
      if (!row) return;
      const details = row.fields.details;
      const record = details && typeof details === "object" ? details : layoutFields(row);
      writeClipboard(JSON.stringify(record, null, 2)).then(
        () => announce("레코드 JSON을 복사했습니다."),
        (error: unknown) => announce(`복사 실패: ${error instanceof Error ? error.message : String(error)}`),
      );
    },
  };

  return (
    <>
      <div className="viewer-actions">
        {/* One review-status chip with its menu (C-W9): "미검토 ▾", not a toggle + a second chip. */}
        <MenuButton
          label={`리뷰 상태: ${currentLabel}`}
          items={statusItems}
          triggerClassName="viewer-status-trigger"
          onDisabled={(reason) => announce(reason)}
          testId="viewer-review-status-menu"
          title={`리뷰 상태: ${currentLabel} — 눌러서 바꾸기`}
        >
          <span
            className="status-chip viewer-status"
            data-status={current ?? undefined}
            data-testid="viewer-review-status"
          >
            {currentLabel}
          </span>
          <Icon name="chevron-down" />
        </MenuButton>
        <span ref={moreRef} className="viewer-actions-more">
          <MenuButton
            label="더보기"
            items={[...reviewItems, ...sourceItems, copyJsonItem, ...pivotItems]}
            triggerClassName="viewer-icon-button"
            onDisabled={(reason) => announce(reason)}
            testId="viewer-actions-menu"
          >
            <Icon name="more" />
          </MenuButton>
        </span>
      </div>
      {noteOpen && target ? (
        <NoteForm onSave={(text) => void saveNote(text)} onCancel={() => setNoteOpen(false)} />
      ) : null}
    </>
  );
}
