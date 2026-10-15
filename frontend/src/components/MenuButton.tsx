/**
 * Menu button (visual-polish S5/S6): one trigger, one role=menu list. ↑/↓/Home/End move,
 * Enter/Space activate, Esc and Tab close and return focus to the trigger. A disabled item
 * stays focusable with aria-disabled + its reason as description, and activating it says the
 * reason (`onDisabled`) instead of doing nothing.
 */

import { type KeyboardEvent, type ReactNode, useEffect, useId, useRef, useState } from "react";
import { useEscape } from "../a11y/focus";
import { Icon, type IconName } from "../icons";
import { keyLabel } from "../shortcuts";
import "./popover.css";

export interface MenuItem {
  id: string;
  label: string;
  /** Korean reason the item cannot run; the item stays listed. */
  disabledReason?: string;
  /** Toggle items (menuitemcheckbox): current state. */
  checked?: boolean;
  /** `data-command` of the item (tests, e2e). */
  command?: string;
  /** Colour hint for review-status items (status dot). */
  status?: string;
  /** Leading glyph; the 16px slot is reserved either way so every label lines up (review #13). */
  icon?: IconName;
  /** Key hint shown right-aligned (registry notation, e.g. "R", "Enter"). */
  shortcut?: string;
  onSelect: () => void;
  /** Rule above the item. */
  separator?: boolean;
  /** Section heading above the item (e.g. "리뷰", "원본"); implies a rule unless it is first. */
  section?: string;
}

export interface MenuButtonProps {
  /** Accessible name of the trigger (and the menu). */
  label: string;
  /** Visible trigger content (an icon, a short word). */
  children: ReactNode;
  items: MenuItem[];
  triggerClassName?: string;
  align?: "start" | "end";
  onDisabled?: (reason: string) => void;
  /** Extra trigger attributes for tests. */
  testId?: string;
  title?: string;
  /** Open upwards (a bar at the bottom of a pane). */
  placement?: "below" | "above";
}

export function MenuButton({
  label,
  children,
  items,
  triggerClassName = "button ghost icon-only",
  align = "end",
  onDisabled,
  testId,
  title,
  placement = "below",
}: MenuButtonProps) {
  const [open, setOpen] = useState(false);
  const menuId = useId();
  const reasonPrefix = useId();
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) triggerRef.current?.focus();
  };

  useEscape(() => close(true), open);

  useEffect(() => {
    if (!open) return;
    menuRef.current?.querySelector<HTMLElement>("[role^=menuitem]")?.focus();
    const onDown = (event: PointerEvent | MouseEvent) => {
      const target = event.target as Node | null;
      if (!target || menuRef.current?.contains(target) || triggerRef.current?.contains(target)) return;
      setOpen(false);
    };
    document.addEventListener("pointerdown", onDown, true);
    return () => document.removeEventListener("pointerdown", onDown, true);
  }, [open]);

  const move = (delta: number | "first" | "last") => {
    const nodes = Array.from(menuRef.current?.querySelectorAll<HTMLElement>("[role^=menuitem]") ?? []);
    if (nodes.length === 0) return;
    const index = nodes.indexOf(document.activeElement as HTMLElement);
    const next =
      delta === "first"
        ? 0
        : delta === "last"
          ? nodes.length - 1
          : (index + delta + nodes.length) % nodes.length;
    nodes[next]?.focus();
  };

  const onMenuKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault();
        move(1);
        break;
      case "ArrowUp":
        event.preventDefault();
        move(-1);
        break;
      case "Home":
        event.preventDefault();
        move("first");
        break;
      case "End":
        event.preventDefault();
        move("last");
        break;
      case "Tab":
        event.preventDefault();
        close(true);
        break;
      default:
        break;
    }
  };

  return (
    <span className="menu-anchor">
      <button
        ref={triggerRef}
        type="button"
        className={triggerClassName}
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        title={title ?? label}
        data-testid={testId}
        onClick={() => setOpen((value) => !value)}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown" && !open) {
            event.preventDefault();
            setOpen(true);
          }
        }}
      >
        {children}
      </button>
      {open ? (
        <div
          ref={menuRef}
          id={menuId}
          role="menu"
          aria-label={label}
          className={`popover menu popover-${align}${placement === "above" ? " popover-above" : ""}`}
          onKeyDown={onMenuKeyDown}
        >
          {items.map((item, index) => {
            const reasonId = `${reasonPrefix}-${index}`;
            const common = {
              type: "button" as const,
              "aria-disabled": item.disabledReason ? true : undefined,
              "aria-keyshortcuts": item.shortcut ? item.shortcut.replace("Ctrl", "Control") : undefined,
              "aria-describedby": item.disabledReason ? reasonId : undefined,
              "data-disabled-reason": item.disabledReason || undefined,
              "data-command": item.command,
              "data-status": item.status,
              tabIndex: -1,
              className: "menu-item",
              onClick: () => {
                if (item.disabledReason) {
                  onDisabled?.(item.disabledReason);
                  return;
                }
                close(true);
                item.onSelect();
              },
            };
            const content = (
              <>
                <span className="menu-item-lead" aria-hidden="true">
                  {item.status ? (
                    <span className="status-dot" data-status={item.status} />
                  ) : item.icon ? (
                    <Icon name={item.icon} />
                  ) : null}
                </span>
                <span className="menu-item-text">
                  <span className="menu-item-label">{item.label}</span>
                  {item.disabledReason ? (
                    <span className="menu-item-reason" aria-hidden="true">
                      {item.disabledReason}
                    </span>
                  ) : null}
                </span>
                {item.checked ? <Icon name="check" className="menu-item-check" /> : null}
                {item.shortcut ? (
                  <span className="menu-item-kbd" aria-hidden="true">
                    {keyLabel(item.shortcut)}
                  </span>
                ) : null}
              </>
            );
            return (
              <div key={item.id} className="menu-row" role="none">
                {(item.separator || item.section) && index > 0 ? <hr className="menu-sep" /> : null}
                {item.section ? (
                  <div className="menu-heading" aria-hidden="true">
                    {item.section}
                  </div>
                ) : null}
                {item.checked === undefined ? (
                  <button role="menuitem" {...common}>
                    {content}
                  </button>
                ) : (
                  <button role="menuitemcheckbox" aria-checked={item.checked} {...common}>
                    {content}
                  </button>
                )}
                {item.disabledReason ? (
                  <span id={reasonId} hidden>
                    {item.disabledReason}
                  </span>
                ) : null}
              </div>
            );
          })}
        </div>
      ) : null}
    </span>
  );
}
