import { Fragment, useEffect, useRef, useState } from "react";
import { useEscape } from "../../a11y/focus";
import { type CommandContext, KEY_MAP } from "../../contracts/command";
import { Icon, type IconName, isIconName } from "../../icons";
import { keyLabel } from "../../shortcuts";
import { getRegisteredCommand } from "./adapter";

/** First-level row-menu entries in order; each is a registered `grid.*` Command. */
export const ROW_MENU_COMMAND_IDS = ["grid.openSource"] as const;

/** Entries behind "고급…", the rarer per-row actions (review: 22 entries on one level). */
export const ROW_MENU_ADVANCED_IDS = [
  "grid.openHex",
  "grid.copyPath",
  "grid.copyCitation",
  "grid.showInTimeline",
  "grid.sameSource",
  "grid.ocrSelected",
] as const;

/**
 * Row-specific entries listed only when they apply to the focused row (no permanently
 * disabled noise on every other row): cross-case rows → "다른 케이스에서 열기".
 */
export const ROW_MENU_CONTEXTUAL_IDS = ["grid.openOtherCase"] as const;

/** Record pivots (viewer redesign §5), behind 고급… › 피벗…; disabled with a reason when absent. */
export const ROW_MENU_PIVOT_IDS = [
  "grid.pivot.same-user",
  "grid.pivot.same-logon",
  "grid.pivot.same-hash",
  "grid.pivot.same-target",
  "grid.pivot.same-key",
  "grid.pivot.same-source",
  "grid.pivot.timeline-window",
  "grid.pivot.matched-event",
  "grid.pivot.source-artifact",
] as const;

/** Review items, always on the first level (disabled with a reason when they cannot run). */
export const ROW_MENU_REVIEW_IDS = [
  "grid.row.relevant",
  "grid.row.needs-review",
  "grid.row.excluded",
  "grid.row.include-in-report",
  "grid.row.bookmark",
] as const;

/** Keys a row-menu entry mirrors (review #13): Enter opens, R / X / I / B mark the row. */
const ROW_MENU_KEYS: Record<string, { command?: string; fallback: string }> = {
  "grid.openSource": { fallback: KEY_MAP.openViewer },
  "grid.row.relevant": { command: "review.mark.relevant", fallback: KEY_MAP.markRelevant },
  "grid.row.excluded": { command: "review.mark.excluded", fallback: KEY_MAP.markExcluded },
  "grid.row.needs-review": { command: "review.mark.needs-review", fallback: KEY_MAP.markNeedsReview },
  "grid.row.bookmark": { command: "review.mark.bookmark", fallback: KEY_MAP.bookmark },
};

/**
 * The key hint of a row-menu entry: the command's own shortcut, else the registered command it
 * mirrors (the shell's review.mark.*), else the KEY_MAP key; undefined when it has none.
 */
export function rowMenuShortcut(id: string, ownShortcut?: string): string | undefined {
  if (ownShortcut) return ownShortcut;
  const entry = ROW_MENU_KEYS[id];
  if (!entry) return undefined;
  return (entry.command ? getRegisteredCommand(entry.command)?.shortcut : undefined) ?? entry.fallback;
}

/** Levels of the menu; "고급…" / "피벗…" open one, "뒤로" returns to its parent. */
type RowMenuStage = "root" | "advanced" | "pivot";

/** One rendered row of the open level: a `grid.*` command, or an entry that changes level. */
interface RowMenuEntry {
  /** `data-command` of the entry (tests, e2e). */
  command: string;
  label: string;
  icon?: IconName;
  shortcut?: string;
  /** Korean reason the entry cannot run; the entry stays listed. */
  reason?: string;
  /** Section heading above the entry; implies a rule unless it is the first entry. */
  section?: string;
  /** Rule above the entry. */
  separator?: boolean;
  run: () => void;
}

export interface RowMenuProps {
  /** Element id, referenced by the trigger's aria-controls. */
  id?: string;
  /** Viewport coordinates; null = closed. */
  anchor: { x: number; y: number } | null;
  context: CommandContext;
  onClose: () => void;
  /** Called with the reason when a disabled item is activated (never a silent no-op). */
  onDisabled: (reason: string) => void;
}

export function RowMenu({ id, anchor, context, onClose, onDisabled }: RowMenuProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [stage, setStage] = useState<RowMenuStage>("root");
  // Esc closes the menu wherever focus went (shared Esc stack), not only from inside it.
  useEscape(onClose, anchor !== null);

  // A closed (or re-anchored) menu opens on its first level again.
  // biome-ignore lint/correctness/useExhaustiveDependencies: reset the level when the menu re-opens
  useEffect(() => setStage("root"), [anchor]);

  // The first entry of the open level takes focus.
  // biome-ignore lint/correctness/useExhaustiveDependencies: refocus when the level changes
  useEffect(() => {
    if (!anchor) return;
    ref.current?.querySelector<HTMLElement>("[role=menuitem]")?.focus();
  }, [anchor, stage]);

  useEffect(() => {
    if (!anchor) return;
    const onDown = (event: MouseEvent) => {
      const target = event.target as Element | null;
      // The trigger toggles the menu itself (its click closes it again).
      if (id && target?.closest?.(`[aria-controls="${id}"]`)) return;
      if (ref.current && !ref.current.contains(target as Node)) onClose();
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [anchor, onClose, id]);

  if (!anchor) return null;

  const entriesOf = (ids: readonly string[], section?: string): RowMenuEntry[] => {
    const entries = ids.flatMap((commandId): RowMenuEntry[] => {
      const command = getRegisteredCommand(commandId);
      if (!command) return [];
      return [
        {
          command: command.id,
          label: command.label,
          icon: isIconName(command.icon) ? command.icon : undefined,
          shortcut: rowMenuShortcut(command.id, command.shortcut),
          reason: command.disabledReason?.(context),
          run: () => {
            onClose();
            void command.run(context);
          },
        },
      ];
    });
    const [first] = entries;
    if (first && section) first.section = section;
    return entries;
  };
  /** Entry that opens another level; "…" marks it as a group, like a submenu. */
  const stageEntry = (
    to: RowMenuStage,
    label: string,
    icon: IconName,
    extra?: Partial<RowMenuEntry>,
  ): RowMenuEntry => ({
    command: `grid.menu.${to}`,
    label: `${label}…`,
    icon,
    run: () => setStage(to),
    ...extra,
  });
  const backEntry = (to: RowMenuStage, section: string): RowMenuEntry => ({
    command: "grid.menu.back",
    label: "뒤로",
    icon: "arrow-left",
    section,
    run: () => setStage(to),
  });

  const entries: RowMenuEntry[] =
    stage === "advanced"
      ? [
          backEntry("root", "고급"),
          ...entriesOf(ROW_MENU_ADVANCED_IDS),
          stageEntry("pivot", "피벗", "filter", { separator: true }),
        ]
      : stage === "pivot"
        ? [backEntry("advanced", "피벗"), ...entriesOf(ROW_MENU_PIVOT_IDS)]
        : [
            ...entriesOf(ROW_MENU_CONTEXTUAL_IDS).filter((entry) => !entry.reason),
            ...entriesOf(ROW_MENU_COMMAND_IDS),
            ...entriesOf(ROW_MENU_REVIEW_IDS, "리뷰"),
            stageEntry("advanced", "고급", "more", { separator: true }),
          ];

  const move = (delta: number, from: HTMLElement) => {
    const nodes = Array.from(ref.current?.querySelectorAll<HTMLElement>("[role=menuitem]") ?? []);
    const index = nodes.indexOf(from);
    nodes[(index + delta + nodes.length) % nodes.length]?.focus();
  };

  return (
    <div
      ref={ref}
      id={id}
      className="grid-menu"
      role="menu"
      aria-label="행 메뉴"
      style={{ left: anchor.x, top: anchor.y }}
      onKeyDown={(event) => {
        const target = event.target as HTMLElement;
        if (event.key === "Escape" || event.key === "Tab") {
          event.preventDefault();
          event.stopPropagation();
          onClose();
        } else if (event.key === "ArrowDown") {
          event.preventDefault();
          move(1, target);
        } else if (event.key === "ArrowUp") {
          event.preventDefault();
          move(-1, target);
        } else if (event.key === "Home") {
          event.preventDefault();
          move(-1000, target);
        }
      }}
    >
      {entries.map((entry, index) => (
        <Fragment key={entry.command}>
          {(entry.section || entry.separator) && index > 0 ? <hr className="grid-menu-sep" /> : null}
          {entry.section ? (
            <div className="menu-heading" aria-hidden="true">
              {entry.section}
            </div>
          ) : null}
          <button
            type="button"
            role="menuitem"
            className="grid-menu-item menu-item"
            aria-disabled={entry.reason ? true : undefined}
            aria-keyshortcuts={entry.shortcut}
            title={entry.reason}
            data-disabled-reason={entry.reason || undefined}
            data-command={entry.command}
            onClick={() => {
              if (entry.reason) {
                onDisabled(entry.reason);
                return;
              }
              entry.run();
            }}
          >
            {/* 16px lead slot (icon or empty), label + 11px reason line, right-aligned key. */}
            <span className="menu-item-lead" aria-hidden="true">
              {entry.icon ? <Icon name={entry.icon} /> : null}
            </span>
            <span className="menu-item-text">
              <span className="menu-item-label">{entry.label}</span>
              {entry.reason ? (
                <span className="menu-item-reason" aria-hidden="true">
                  {entry.reason}
                </span>
              ) : null}
            </span>
            {entry.shortcut ? (
              <span className="menu-item-kbd" aria-hidden="true">
                {keyLabel(entry.shortcut)}
              </span>
            ) : null}
          </button>
        </Fragment>
      ))}
    </div>
  );
}
