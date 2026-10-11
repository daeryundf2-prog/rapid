import { useEffect, useRef } from "react";
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
] as const;

export interface RowMenuProps {
  /** Viewport coordinates; null = closed. */
  anchor: { x: number; y: number } | null;
  context: CommandContext;
  onClose: () => void;
  /** Called with the reason when a disabled item is activated (never a silent no-op). */
  onDisabled: (reason: string) => void;
}

export function RowMenu({ anchor, context, onClose, onDisabled }: RowMenuProps) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!anchor) return;
    ref.current?.querySelector<HTMLElement>("[role=menuitem]")?.focus();
    const onDown = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) onClose();
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [anchor, onClose]);

  if (!anchor) return null;

  const items = ROW_MENU_COMMAND_IDS.map((id) => getRegisteredCommand(id)).filter(
    (command): command is NonNullable<typeof command> => !!command,
  );

  const move = (delta: number, from: HTMLElement) => {
    const nodes = Array.from(ref.current?.querySelectorAll<HTMLElement>("[role=menuitem]") ?? []);
    const index = nodes.indexOf(from);
    nodes[(index + delta + nodes.length) % nodes.length]?.focus();
  };

  return (
    <div
      ref={ref}
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
      {items.map((command) => {
        const reason = command.disabledReason?.(context);
        return (
          <button
            key={command.id}
            type="button"
            role="menuitem"
            className="grid-menu-item"
            aria-disabled={reason ? true : undefined}
            title={reason}
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
        );
      })}
    </div>
  );
}
