/**
 * Viewer actions (visual-polish S5/S6, review #6) — one cluster at the right of the viewer header:
 *  - "관련 있음": the one review action kept as a primary toggle (the batch bar owns the rest);
 *  - a status chip (dot + text): the row's current review status;
 *  - one "⋯" menu (더보기) with two sections — 리뷰: 재검토 · 제외 · 보고서 포함 · 북마크 · 메모,
 *    and 원본: 원본 열기 · 해시 복사 · 경로 복사 · 인용 복사 · 같은 출처의 다른 행.
 * Every entry is a view of a registered Command (same ids as before), so the palette, the key
 * map and this menu run the same code; key hints come from the registry.
 */

import { useEffect, useRef, useState } from "react";
import { announce, DisabledReason } from "../../a11y";
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
import { VIEWER_COMMAND_IDS, writeClipboard } from "./commands";
import { layoutFields } from "./fieldSheets";
import { PARTIAL_COPY_REASON, useFullRecordStatus } from "./fullRecord";
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
 * "같은 해시 행에 전파" section of the viewer menu, always on the viewer row: the default entry
 * spreads every user tag of the row; then one entry per tag on the row (system tags 북마크 ·
 * 우선순위 n only this way) so the examiner chooses what spreads.
 */
export function propagationItems(row: GridRow | null, runId: string | null): MenuItem[] {
  const rows = row ? [row] : [];
  const user = defaultPropagationTags(rows);
  const all: MenuItem = {
    id: PROPAGATE_COMMAND,
    label: user.length
      ? `같은 해시 행에 태그 전파: 사용자 태그 전부 (${user.join(", ")})`
      : "같은 해시 행에 태그 전파",
    command: PROPAGATE_COMMAND,
    icon: "tag",
    section: "같은 해시 행에 전파",
    disabledReason: propagateReason(runId, rows),
    onSelect: () => void runPropagation(runId, rows),
  };
  const each = (row?.tags ?? []).map(
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

/**
 * Levels of the 더보기 menu (review: one flat list of 20+ entries). MenuButton has no nested
 * menus, so the one menu swaps its items: the first level keeps the frequent entries and two
 * 복사… / 고급… entries open the rarer ones, each with a 뒤로 entry back to its parent level.
 */
type MenuStage = "root" | "copy" | "advanced" | "pivot";
const STAGE_BACK: Record<Exclude<MenuStage, "root">, MenuStage> = {
  copy: "root",
  advanced: "root",
  pivot: "advanced",
};

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
  const partialRecord = useFullRecordStatus(row, target?.runId ?? null);
  const { route, navigate } = useRoute();
  const [noteOpen, setNoteOpen] = useState(false);
  const [stage, setStage] = useState<MenuStage>("root");
  /** Bumped by a stage entry; the effect re-opens the menu on the new level. */
  const [reopen, setReopen] = useState(0);
  const reopening = useRef(false);
  const [applied, setApplied] = useState<{ key: string; actions: string[]; cleared: string[] }>({
    key: "",
    actions: [],
    cleared: [],
  });
  const moreRef = useRef<HTMLSpanElement>(null);
  const key = target ? noteKey(target.runId, target.ref) : "";
  const noteReason = target ? markDisabledReason(target, "relevant") : "뷰어에 표시된 행이 없습니다.";

  // A different row closes the form and returns the menu to its first level.
  // biome-ignore lint/correctness/useExhaustiveDependencies: close on target change only
  useEffect(() => {
    setNoteOpen(false);
    setStage("root");
  }, [key]);

  // MenuButton closes on every activation, so a stage entry clicks the trigger again.
  useEffect(() => {
    if (reopen === 0) return;
    reopening.current = true;
    moreRef.current?.querySelector<HTMLButtonElement>('button[aria-haspopup="menu"]')?.click();
    reopening.current = false;
  }, [reopen]);

  const goStage = (next: MenuStage) => {
    setStage(next);
    setReopen((count) => count + 1);
  };

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

  /** The key that marks the row (R / X / I / B): the viewer command's own, else the shell's review.mark.*. */
  const markShortcut = (command: Command, action: string) =>
    command.shortcut ?? getCommand(`review.mark.${action}`)?.shortcut;

  const markItems: MenuItem[] = others.map((command, index) => {
    const action = markOf(command);
    return {
      id: command.id,
      label: command.label.replace(/^표시: /, ""),
      command: command.id,
      status: action,
      checked: isPressed(action),
      shortcut: markShortcut(command, action),
      disabledReason: command.disabledReason?.(ctx),
      section: index === 0 ? "리뷰" : undefined,
      onSelect: () => run(command),
    };
  });

  const noteItem: MenuItem = {
    id: "viewer.note",
    label: "메모…",
    command: "viewer.note",
    icon: "message",
    disabledReason: noteReason,
    onSelect: () => setNoteOpen(true),
  };

  // Review tools (AXIOM E3): note history with author/time, tag manager.
  const reviewToolItems: MenuItem[] = [NOTE_PANEL_COMMAND, TAG_MANAGER_COMMAND].map((id, index): MenuItem => {
    const command = getCommand(id);
    return {
      id,
      label: command?.label ?? id,
      command: id,
      icon: id === NOTE_PANEL_COMMAND ? "clock" : "tag",
      section: index === 0 ? "리뷰 도구" : undefined,
      disabledReason: command ? command.disabledReason?.(ctx) : POPOUT_ONLY_REASON,
      onSelect: () => void runCommand(id),
    };
  });

  const sourceItem = (command: Command, section?: string): MenuItem => ({
    id: command.id,
    label: command.label,
    command: command.id,
    icon: isIconName(command.icon) ? command.icon : undefined,
    shortcut: command.shortcut,
    disabledReason: command.disabledReason?.(ctx),
    section,
    onSelect: () => run(command),
  });
  // 원본 열기 stays on the first level; the copies move behind 복사….
  const openCommand = sourceCommands.find((command) => command.id === VIEWER_COMMAND_IDS.openOriginal);
  const copyCommands = sourceCommands.filter((command) => command !== openCommand);

  const rowsForSourceItem: MenuItem = {
    id: "navigate.rows-for-source",
    label: "같은 출처의 다른 행",
    command: "navigate.rows-for-source",
    icon: "list",
    disabledReason: rowsForSource.reason,
    onSelect: rowsForSource.run,
  };

  // Pivots (viewer redesign §5): the same list as the grid row menu, each with its reason.
  const pivotItems: MenuItem[] = recordPivots(target ? row : null, target?.runId ?? "", route.tz).map(
    (pivot) => ({
      id: `viewer.pivot.${pivot.id}`,
      label: pivot.value
        ? `${pivot.label}: ${pivot.value.length > 40 ? `${pivot.value.slice(0, 39)}…` : pivot.value}`
        : pivot.label,
      command: `viewer.pivot.${pivot.id}`,
      icon: PIVOT_ICONS[pivot.id],
      disabledReason: pivot.reason,
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
    disabledReason: !row
      ? "뷰어에 표시된 레코드가 없습니다."
      : partialRecord
        ? PARTIAL_COPY_REASON
        : undefined,
    onSelect: () => {
      if (!row || partialRecord) return;
      const details = row.fields.details;
      const record = details && typeof details === "object" ? details : layoutFields(row);
      writeClipboard(JSON.stringify(record, null, 2)).then(
        () => announce("레코드 JSON을 복사했습니다."),
        (error: unknown) => announce(`복사 실패: ${error instanceof Error ? error.message : String(error)}`),
      );
    },
  };

  /** Entry that opens another level of the menu; "…" marks it as a group, like a submenu. */
  const stageItem = (
    to: Exclude<MenuStage, "root">,
    label: string,
    icon: MenuItem["icon"],
    extra?: Partial<MenuItem>,
  ): MenuItem => ({
    id: `viewer.menu.${to}`,
    label: `${label}…`,
    command: `viewer.menu.${to}`,
    icon,
    onSelect: () => goStage(to),
    ...extra,
  });
  const backItem = (from: Exclude<MenuStage, "root">, section: string): MenuItem => ({
    id: "viewer.menu.back",
    label: "뒤로",
    command: "viewer.menu.back",
    icon: "arrow-left",
    section,
    onSelect: () => goStage(STAGE_BACK[from]),
  });

  /** The entries of the open level: eight on the first one, the rest behind 복사… / 고급…. */
  const menuItems: MenuItem[] =
    stage === "copy"
      ? [backItem("copy", "복사"), ...copyCommands.map((command) => sourceItem(command)), copyJsonItem]
      : stage === "advanced"
        ? [
            backItem("advanced", "고급"),
            rowsForSourceItem,
            stageItem("pivot", "피벗", "filter"),
            ...reviewToolItems,
            ...propagationItems(target ? (row ?? targetAsGridRow(target)) : null, target?.runId ?? null),
          ]
        : stage === "pivot"
          ? [backItem("pivot", "피벗"), ...pivotItems]
          : [
              ...markItems,
              noteItem,
              ...(openCommand ? [sourceItem(openCommand, "원본")] : []),
              stageItem("copy", "복사", "copy"),
              stageItem("advanced", "고급", "more", { separator: true }),
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
        {/* Status as a chip with text (review #6), not a bare dot. */}
        <span
          className="status-chip viewer-status"
          data-status={current ?? undefined}
          role="img"
          aria-label={`리뷰 상태: ${currentLabel}`}
          title={`리뷰 상태: ${currentLabel}`}
          data-testid="viewer-review-status"
        >
          {currentLabel}
        </span>
        {/* Opening the menu by hand always starts on the first level (Esc can leave it deeper). */}
        <span
          ref={moreRef}
          className="viewer-actions-more"
          onClickCapture={(event) => {
            if (reopening.current) return;
            if ((event.target as HTMLElement).closest('[aria-haspopup="menu"]')) setStage("root");
          }}
          onKeyDownCapture={(event) => {
            if (event.key !== "ArrowDown") return;
            if ((event.target as HTMLElement).closest('[aria-haspopup="menu"]')) setStage("root");
          }}
        >
          <MenuButton
            label="더보기"
            items={menuItems}
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
