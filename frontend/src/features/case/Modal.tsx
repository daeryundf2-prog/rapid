import { type KeyboardEvent, type ReactNode, useEffect, useId, useRef } from "react";
import { Icon } from "../../icons";
import "./case.css";

const FIELD = "input:not([disabled]):not([type='hidden']), select:not([disabled]), textarea:not([disabled])";
const FOCUSABLE =
  "a[href], button:not([disabled]), input:not([disabled]):not([type='hidden']), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex='-1'])";

/** Marks the safe action a destructive dialog starts on (`initialFocus="cancel"`). */
const DIALOG_CANCEL_ATTR = "data-dialog-cancel";

/** Hidden by `hidden`, `inert`, `display:none` or `visibility:hidden` on it or an ancestor inside `root`. */
function isHidden(element: HTMLElement, root: HTMLElement): boolean {
  for (let node: HTMLElement | null = element; node && node !== root; node = node.parentElement) {
    if (node.hidden || node.hasAttribute("inert")) return true;
    const style = getComputedStyle(node);
    if (style.display === "none" || style.visibility === "hidden") return true;
  }
  return false;
}

/** `a` comes before `b` in document order (`b` not inside `a`); a missing `a` precedes everything. */
function isBefore(a: Element | null, b: Element | null): boolean {
  if (!a || !b || a === b) return !a && !!b;
  const position = a.compareDocumentPosition(b);
  return (
    (position & Node.DOCUMENT_POSITION_FOLLOWING) !== 0 &&
    (position & Node.DOCUMENT_POSITION_CONTAINED_BY) === 0
  );
}

/**
 * The dialog's Tab cycle (T-034): focusable elements in DOM order, minus `aria-disabled="true"` and
 * hidden ones; a named radio group contributes one stop (its checked radio, else its first), like
 * the browser's own Tab order.
 */
function tabStops(root: HTMLElement): HTMLElement[] {
  const seenGroups = new Set<string>();
  const radios = new Map<string, HTMLInputElement[]>();
  const candidates = [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(
    (element) => element.getAttribute("aria-disabled") !== "true" && !isHidden(element, root),
  );
  for (const element of candidates) {
    if (element instanceof HTMLInputElement && element.type === "radio" && element.name) {
      radios.set(element.name, [...(radios.get(element.name) ?? []), element]);
    }
  }
  return candidates.filter((element) => {
    if (!(element instanceof HTMLInputElement && element.type === "radio" && element.name)) return true;
    if (seenGroups.has(element.name)) return false;
    const group = radios.get(element.name) ?? [];
    const stop = group.find((radio) => radio.checked) ?? group[0];
    if (stop !== element) return false;
    seenGroups.add(element.name);
    return true;
  });
}

/** Minimal accessible modal: labelled dialog, Esc closes, Tab is trapped, focus is restored. */
export function Modal({
  title,
  onClose,
  children,
  wide = false,
  footer,
  initialFocus = "first-input",
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
  /** Action row under a hairline (review #4): 취소 + the one primary action, right-aligned. */
  footer?: ReactNode;
  /**
   * Where focus starts (design system: Dialog `initialFocus`). "first-input" = the first form field,
   * else the first tab stop. "cancel" = the element marked `data-dialog-cancel` — a destructive
   * confirm starts on the safe action so Enter on an unread dialog never deletes (T-034).
   */
  initialFocus?: "first-input" | "cancel";
}) {
  const titleId = useId();
  const ref = useRef<HTMLDivElement>(null);

  // biome-ignore lint/correctness/useExhaustiveDependencies: mount-only — the starting focus is chosen once, when the dialog opens
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const root = ref.current;
    const cancel =
      initialFocus === "cancel" ? root?.querySelector<HTMLElement>(`[${DIALOG_CANCEL_ATTR}]`) : null;
    // Start on the first form field (not the header's 닫기 button); no field → first tab stop.
    const stops = root ? tabStops(root) : [];
    const body = root?.querySelector(".case-modal-body");
    const field = stops.find((element) => body?.contains(element) && element.matches(FIELD));
    const first = cancel ?? field ?? stops[0];
    (first ?? root)?.focus();
    return () => previous?.focus?.();
  }, []);

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.stopPropagation();
      onClose();
      return;
    }
    // A nested dialog or widget that already moved focus keeps it.
    if (event.key !== "Tab" || !ref.current || event.defaultPrevented) return;
    // The whole Tab cycle is managed so aria-disabled and hidden elements are never stops and
    // focus never leaves the dialog (T-034).
    event.preventDefault();
    const items = tabStops(ref.current);
    if (items.length === 0) return;
    const active = document.activeElement;
    let next: HTMLElement | undefined;
    if (event.shiftKey) {
      // Last stop before the focused element (it may itself be a non-stop, e.g. a roving item).
      next = [...items].reverse().find((item) => isBefore(item, active)) ?? items[items.length - 1];
    } else {
      next = items.find((item) => isBefore(active, item)) ?? items[0];
    }
    next?.focus();
  };

  return (
    <div className="case-modal-backdrop">
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={`case-modal${wide ? " wide" : ""}`}
        onKeyDown={onKeyDown}
      >
        <header className="case-modal-header">
          <h2 id={titleId}>{title}</h2>
          <button type="button" className="icon-btn" aria-label="닫기" onClick={onClose}>
            <Icon name="close" />
          </button>
        </header>
        <div className="case-modal-body">{children}</div>
        {footer ? <footer className="case-modal-footer">{footer}</footer> : null}
      </div>
    </div>
  );
}
