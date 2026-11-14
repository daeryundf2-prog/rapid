import { Fragment, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useEscape } from "../../a11y/focus";
import { placePopover } from "../../components/Popover";
import { type Command, type CommandContext, KEY_MAP } from "../../contracts/command";
import { Icon, isIconName } from "../../icons";
import { commandReadOnlyReason } from "../../shell/readOnly";
import { keyLabel } from "../../shortcuts";
import { getRegisteredCommand } from "./adapter";

/**
 * The row menu's first level (plan r8 T-090, IS-026): eight entries — 열기 · 관련 있음 · 재검토 ·
 * 제외 · 태그 · 보고서 포함 · 전후 시각 · 같은 파일 — then "더 보기". Entries that cannot run on
 * the focused row are not listed (no disabled noise); each is a registered `grid.*` Command.
 * Exception (T-348): a write entry blocked only because the result / server is read-only stays
 * listed, disabled with the read-only sentence, so the examiner sees why marking is off.
 */
export const ROW_MENU_PRIMARY_IDS = [
  "grid.openSource",
  "grid.row.relevant",
  "grid.row.needs-review",
  "grid.row.excluded",
  "grid.row.tag",
  "grid.row.include-in-report",
  "grid.pivot.timeline-window",
  "grid.pivot.same-source",
] as const;

/** Entries that only apply to some rows: cross-case rows → "다른 케이스에서 열기". */
export const ROW_MENU_CONTEXTUAL_IDS = ["grid.openOtherCase"] as const;

/** "더 보기": every other row command, in this order, listed only when it can run. */
export const ROW_MENU_MORE_IDS = [
  ...ROW_MENU_CONTEXTUAL_IDS,
  "grid.openHex",
  "grid.copyPath",
  "grid.copyCitation",
  "grid.showInTimeline",
  "grid.sameSource",
  // 계열 (R7 갈래 A): the row's family / parent item; the selection's families.
  "grid.family.view",
  "grid.family.parent",
  "grid.family.expandSelection",
  "grid.ocrSelected",
  // Record pivots (viewer redesign §5) not on the first level.
  "grid.pivot.same-user",
  "grid.pivot.same-logon",
  "grid.pivot.same-hash",
  "grid.pivot.same-target",
  "grid.pivot.same-key",
  "grid.pivot.matched-event",
  "grid.pivot.source-artifact",
  "grid.row.bookmark",
] as const;

/** Label of the entry that reveals ROW_MENU_MORE_IDS. */
export const ROW_MENU_MORE_LABEL = "더 보기";

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

/** A row-menu entry: a runnable command, or a write command disabled by the read-only sentence. */
export interface RowMenuEntry {
  command: Command;
  /** The read-only sentence (T-348); undefined = runnable. */
  reason?: string;
}

/**
 * The registered, currently runnable commands of `ids` (an entry that cannot run is not listed),
 * plus the write commands whose only block is read-only (T-348): those stay listed with the
 * sentence instead of disappearing.
 */
export function rowMenuEntries(ids: readonly string[], context: CommandContext): RowMenuEntry[] {
  const entries: RowMenuEntry[] = [];
  for (const id of ids) {
    const command = getRegisteredCommand(id);
    if (!command) continue;
    const reason = command.disabledReason?.(context);
    if (!reason) entries.push({ command });
    else if (reason === commandReadOnlyReason(id)) entries.push({ command, reason });
  }
  return entries;
}

export interface RowMenuProps {
  /** Element id, referenced by the trigger's aria-controls. */
  id?: string;
  /**
   * Viewport coordinates; null = closed. x/y is the point the menu hangs from (below a trigger,
   * or the pointer); `top` is the trigger's top edge, used when the menu flips above it.
   */
  anchor: { x: number; y: number; top?: number } | null;
  context: CommandContext;
  onClose: () => void;
  /** Called with the reason when an entry stopped being runnable while the menu was open. */
  onDisabled: (reason: string) => void;
}

export function RowMenu(props: RowMenuProps) {
  // Remount per opening so "더 보기" starts collapsed every time.
  if (!props.anchor) return null;
  return <RowMenuPanel key={`${props.anchor.x},${props.anchor.y}`} {...props} anchor={props.anchor} />;
}

function RowMenuPanel({
  id,
  anchor,
  context,
  onClose,
  onDisabled,
}: RowMenuProps & { anchor: NonNullable<RowMenuProps["anchor"]> }) {
  const ref = useRef<HTMLDivElement>(null);
  const [expanded, setExpanded] = useState(false);
  // Esc closes the menu wherever focus went (shared Esc stack), not only from inside it.
  useEscape(onClose, true);

  // Portalled and placed before paint: below the point, flipped above the trigger when there is
  // more room there, shifted into the viewport and capped (scrolls) — never off screen (IS-102).
  useLayoutEffect(() => {
    const place = () => {
      const menu = ref.current;
      if (!menu) return;
      const next = placePopover(
        { top: anchor.top ?? anchor.y, bottom: anchor.y, left: anchor.x, right: anchor.x },
        { width: menu.offsetWidth, height: menu.scrollHeight },
        { width: window.innerWidth, height: window.innerHeight },
        "start",
      );
      menu.style.top = `${next.top}px`;
      menu.style.left = `${next.left}px`;
      menu.style.maxHeight = `${next.maxHeight}px`;
      menu.dataset.placement = next.above ? "above" : "below";
    };
    place();
    window.addEventListener("resize", place);
    // "더 보기" grows the menu: re-place (flip / cap) when its size changes.
    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(place);
    if (observer && ref.current) observer.observe(ref.current);
    return () => {
      window.removeEventListener("resize", place);
      observer?.disconnect();
    };
  }, [anchor]);

  useEffect(() => {
    ref.current?.querySelector<HTMLElement>("[role=menuitem]")?.focus();
    const onDown = (event: MouseEvent) => {
      const target = event.target as Element | null;
      // The trigger toggles the menu itself (its click closes it again).
      if (id && target?.closest?.(`[aria-controls="${id}"]`)) return;
      if (ref.current && !ref.current.contains(target as Node)) onClose();
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [onClose, id]);

  // After "더 보기", focus the first revealed entry.
  useEffect(() => {
    if (expanded) ref.current?.querySelector<HTMLElement>("[data-more-first]")?.focus();
  }, [expanded]);

  const primary = rowMenuEntries(ROW_MENU_PRIMARY_IDS, context);
  const more = rowMenuEntries(ROW_MENU_MORE_IDS, context);

  const move = (delta: number, from: HTMLElement) => {
    const nodes = Array.from(ref.current?.querySelectorAll<HTMLElement>("[role=menuitem]") ?? []);
    const index = nodes.indexOf(from);
    nodes[(index + delta + nodes.length) % nodes.length]?.focus();
  };

  const item = ({ command, reason: blocked }: RowMenuEntry, first = false) => {
    const shortcut = rowMenuShortcut(command.id, command.shortcut);
    const reasonId = `${id ?? "row-menu"}-${command.id}-reason`;
    return (
      <button
        key={command.id}
        type="button"
        role="menuitem"
        className="grid-menu-item menu-item"
        aria-keyshortcuts={shortcut}
        aria-disabled={blocked ? true : undefined}
        aria-describedby={blocked ? reasonId : undefined}
        data-disabled-reason={blocked}
        data-command={command.id}
        data-more-first={first || undefined}
        onClick={() => {
          // State can change while the menu is open: never run a command that cannot run.
          const reason = command.disabledReason?.(context);
          if (reason) {
            onDisabled(reason);
            return;
          }
          onClose();
          void command.run(context);
        }}
      >
        {/* 16px lead slot (icon or empty), label, right-aligned key. */}
        <span className="menu-item-lead" aria-hidden="true">
          {isIconName(command.icon) ? <Icon name={command.icon} /> : null}
        </span>
        <span className="menu-item-text">
          <span className="menu-item-label">{command.label}</span>
          {blocked ? (
            <span className="menu-item-reason" aria-hidden="true">
              {blocked}
            </span>
          ) : null}
          {blocked ? (
            <span id={reasonId} hidden>
              {blocked}
            </span>
          ) : null}
        </span>
        {shortcut ? (
          <span className="menu-item-kbd" aria-hidden="true">
            {keyLabel(shortcut)}
          </span>
        ) : null}
      </button>
    );
  };

  const panel = (
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
          ref.current?.querySelector<HTMLElement>("[role=menuitem]")?.focus();
        } else if (event.key === "End") {
          event.preventDefault();
          const nodes = ref.current?.querySelectorAll<HTMLElement>("[role=menuitem]");
          nodes?.[nodes.length - 1]?.focus();
        } else if (event.key === "ArrowRight" && target.dataset.more !== undefined) {
          event.preventDefault();
          setExpanded(true);
        }
      }}
    >
      {primary.map((entry) => item(entry))}
      {more.length > 0 && !expanded ? (
        <button
          type="button"
          role="menuitem"
          className="grid-menu-item menu-item"
          aria-haspopup="menu"
          aria-expanded={false}
          data-more=""
          onClick={() => setExpanded(true)}
        >
          <span className="menu-item-lead" aria-hidden="true">
            <Icon name="more" />
          </span>
          <span className="menu-item-text">
            <span className="menu-item-label">{ROW_MENU_MORE_LABEL}</span>
          </span>
        </button>
      ) : null}
      {expanded && more.length > 0 ? (
        <Fragment>
          {primary.length > 0 ? <hr className="grid-menu-sep" /> : null}
          {more.map((entry, index) => item(entry, index === 0))}
        </Fragment>
      ) : null}
    </div>
  );

  return typeof document !== "undefined" ? createPortal(panel, document.body) : panel;
}
