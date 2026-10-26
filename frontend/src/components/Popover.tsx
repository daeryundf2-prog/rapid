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

import {
  type CSSProperties,
  type KeyboardEvent,
  type ReactNode,
  type RefObject,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
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
  /**
   * Render into document.body, fixed to the trigger (plan r7 §3.2 L2, C-D4): above every pane
   * (the viewer included) and never clipped by the grid pane; placed below the trigger, flipped
   * above when there is more room there, and kept inside the viewport horizontally.
   */
  portal?: boolean;
  children: ReactNode;
}

/** Viewport margin of a portalled popover. */
const VIEWPORT_MARGIN = 8;
const TRIGGER_GAP = 4;

export interface PopoverPlacement {
  top: number;
  left: number;
  maxHeight: number;
  above: boolean;
}

/**
 * Where a portalled popover goes (fixed coordinates): below the trigger unless it does not fit
 * there and there is more room above (flip); horizontally aligned to the trigger's start / end
 * edge, then clamped into the viewport.
 */
export function placePopover(
  trigger: { top: number; bottom: number; left: number; right: number },
  panel: { width: number; height: number },
  viewport: { width: number; height: number },
  align: "start" | "end",
): PopoverPlacement {
  const below = viewport.height - trigger.bottom - TRIGGER_GAP - VIEWPORT_MARGIN;
  const aboveRoom = trigger.top - TRIGGER_GAP - VIEWPORT_MARGIN;
  const above = panel.height > below && aboveRoom > below;
  const maxHeight = Math.max(120, Math.floor(above ? aboveRoom : below));
  const height = Math.min(panel.height, maxHeight);
  const top = above ? trigger.top - TRIGGER_GAP - height : trigger.bottom + TRIGGER_GAP;
  const wanted = align === "end" ? trigger.right - panel.width : trigger.left;
  const left = Math.max(VIEWPORT_MARGIN, Math.min(wanted, viewport.width - VIEWPORT_MARGIN - panel.width));
  return { top: Math.max(VIEWPORT_MARGIN, top), left, maxHeight, above };
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
  portal = false,
  children,
}: PopoverProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [placement, setPlacement] = useState<PopoverPlacement | null>(null);

  // Portalled: follow the trigger (resize, any scroll, the panel's own size changes).
  useLayoutEffect(() => {
    if (!open || !portal) {
      setPlacement(null);
      return;
    }
    const place = () => {
      const trigger = triggerRef.current;
      const panel = ref.current;
      if (!trigger || !panel) return;
      const rect = trigger.getBoundingClientRect();
      const next = placePopover(
        rect,
        { width: panel.offsetWidth, height: panel.scrollHeight },
        { width: window.innerWidth, height: window.innerHeight },
        align,
      );
      setPlacement((prev) =>
        prev &&
        prev.top === next.top &&
        prev.left === next.left &&
        prev.maxHeight === next.maxHeight &&
        prev.above === next.above
          ? prev
          : next,
      );
    };
    place();
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(place);
    if (observer && ref.current) observer.observe(ref.current);
    return () => {
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", place, true);
      observer?.disconnect();
    };
  }, [open, portal, align, triggerRef]);
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

  const style: CSSProperties | undefined = portal
    ? placement
      ? { top: placement.top, left: placement.left, maxHeight: placement.maxHeight }
      : { top: 0, left: 0, visibility: "hidden" }
    : undefined;
  const panel = (
    <div
      ref={ref}
      id={id}
      role="dialog"
      aria-label={label}
      tabIndex={-1}
      className={`popover popover-${align}${portal ? " popover-portal" : ""}${className ? ` ${className}` : ""}`}
      data-placement={portal && placement ? (placement.above ? "above" : "below") : undefined}
      style={style}
      onKeyDown={onKeyDown}
    >
      {children}
    </div>
  );
  return portal && typeof document !== "undefined" ? createPortal(panel, document.body) : panel;
}
