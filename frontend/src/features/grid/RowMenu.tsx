import { Fragment, useEffect, useRef } from "react";
import { useEscape } from "../../a11y/focus";
import type { CommandContext } from "../../contracts/command";
import { getRegisteredCommand } from "./adapter";

/** Row-menu entries in order; each is a registered `grid.*` Command. */
export const ROW_MENU_COMMAND_IDS = [
  "grid.openSource",
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

/** Review items, always listed after a separator (disabled with a reason when they cannot run). */
export const ROW_MENU_REVIEW_IDS = [
  "grid.row.relevant",
  "grid.row.needs-review",
  "grid.row.excluded",
  "grid.row.include-in-report",
  "grid.row.bookmark",
] as const;

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
  // Esc closes the menu wherever focus went (shared Esc stack), not only from inside it.
  useEscape(onClose, anchor !== null);

  useEffect(() => {
    if (!anchor) return;
    ref.current?.querySelector<HTMLElement>("[role=menuitem]")?.focus();
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

  const registered = (ids: readonly string[]) =>
    ids
      .map((id) => getRegisteredCommand(id))
      .filter((command): command is NonNullable<typeof command> => !!command);
  const items = [
    ...registered(ROW_MENU_CONTEXTUAL_IDS).filter((command) => !command.disabledReason?.(context)),
    ...registered(ROW_MENU_COMMAND_IDS),
  ];
  const reviewItems = registered(ROW_MENU_REVIEW_IDS);

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
      {[...items, ...reviewItems].map((command, index) => {
        const reason = command.disabledReason?.(context);
        return (
          <Fragment key={command.id}>
            {index === items.length && items.length > 0 ? <hr className="grid-menu-sep" /> : null}
            <button
              type="button"
              role="menuitem"
              className="grid-menu-item"
              aria-disabled={reason ? true : undefined}
              title={reason}
              data-disabled-reason={reason || undefined}
              data-command={command.id}
              onClick={() => {
                if (reason) {
                  onDisabled(reason);
                  return;
                }
                onClose();
                void command.run(context);
              }}
            >
              {command.label}
            </button>
          </Fragment>
        );
      })}
    </div>
  );
}
