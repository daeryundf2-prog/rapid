/**
 * Anchored, non-modal popover (visual-polish S1/S3/S7): the filter popover, the grid column
 * menu and the search options all share one keyboard contract.
 *
 *  - The trigger is a button with aria-expanded / aria-controls / aria-haspopup="dialog";
 *    Enter or Space on it opens the popover (native button activation).
 *  - Opening moves focus to the first control inside; Tab / Shift+Tab cycle inside it.
 *  - Esc closes it and returns focus to the trigger; a pointer press outside closes it
 *    without moving focus (the trigger itself toggles).
 */

import { type KeyboardEvent, type ReactNode, type RefObject, useEffect, useRef } from "react";
import { useEscape } from "../a11y/focus";
import { getTabbables } from "../a11y/focusable";
import "./popover.css";

export interface PopoverProps {
  id: string;
  open: boolean;
  onClose: () => void;
  /** The button that opened the popover; Esc returns focus to it. */
  triggerRef: RefObject<HTMLElement | null>;
  /** Accessible name of the dialog. */
  label: string;
  /** Edge of the anchor the panel lines up with. */
  align?: "start" | "end";
  className?: string;
  /** Initial focus target inside the panel (selector); default: the first control. */
  initialFocus?: string;
  children: ReactNode;
}

export function Popover({
  id,
  open,
  onClose,
  triggerRef,
  label,
  align = "start",
  className,
  initialFocus,
  children,
}: PopoverProps) {
  const ref = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEscape(() => {
    closeRef.current();
    triggerRef.current?.focus();
  }, open);

  // biome-ignore lint/correctness/useExhaustiveDependencies: focus once per opening
  useEffect(() => {
    if (!open) return;
    const root = ref.current;
    if (!root) return;
    const first =
      (initialFocus ? root.querySelector<HTMLElement>(initialFocus) : null) ?? getTabbables(root)[0] ?? root;
    first.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onDown = (event: PointerEvent | MouseEvent) => {
      const target = event.target as Node | null;
      if (!target) return;
      if (ref.current?.contains(target)) return;
      if (triggerRef.current?.contains(target)) return; // the trigger toggles on its own click
      closeRef.current();
    };
    document.addEventListener("pointerdown", onDown, true);
    return () => document.removeEventListener("pointerdown", onDown, true);
  }, [open, triggerRef]);

  if (!open) return null;

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== "Tab") return;
    const root = ref.current;
    if (!root) return;
    const tabbables = getTabbables(root);
    if (tabbables.length === 0) {
      event.preventDefault();
      return;
    }
    const first = tabbables[0] as HTMLElement;
    const last = tabbables[tabbables.length - 1] as HTMLElement;
    const active = document.activeElement;
    // Focus may start on a non-tabbable heading (initialFocus): Shift+Tab from it wraps too.
    const outside = !tabbables.includes(active as HTMLElement);
    if (event.shiftKey && (active === first || active === root || outside)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && active === last) {
      event.preventDefault();
      first.focus();
    }
  };

  return (
    <div
      ref={ref}
      id={id}
      role="dialog"
      aria-label={label}
      tabIndex={-1}
      className={`popover popover-${align}${className ? ` ${className}` : ""}`}
      onKeyDown={onKeyDown}
    >
      {children}
    </div>
  );
}
