import { type RefObject, useCallback, useEffect, useRef } from "react";
import { getTabbables } from "./focusable";

export interface FocusTrapOptions {
  active: boolean;
  /** Element, ref, or selector to focus on activation. Default: first tabbable, else the container. */
  initialFocus?: RefObject<HTMLElement | null> | HTMLElement | string | null;
  /** Restore focus to the previously focused element on deactivate/unmount (default true). */
  returnFocus?: boolean;
}

function resolveInitial(root: HTMLElement, spec: FocusTrapOptions["initialFocus"]): HTMLElement | null {
  if (!spec) return null;
  if (typeof spec === "string") return root.querySelector<HTMLElement>(spec);
  if (spec instanceof HTMLElement) return spec;
  return spec.current;
}

export function useFocusTrap(ref: RefObject<HTMLElement | null>, options: FocusTrapOptions): void {
  const { active, initialFocus, returnFocus = true } = options;
  const initialRef = useRef(initialFocus);
  initialRef.current = initialFocus;

  useEffect(() => {
    const root = ref.current;
    if (!active || !root) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (!root.hasAttribute("tabindex")) root.setAttribute("tabindex", "-1");
    const first = resolveInitial(root, initialRef.current) ?? getTabbables(root)[0] ?? root;
    first.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const tabbables = getTabbables(root);
      if (tabbables.length === 0) {
        event.preventDefault();
        root.focus();
        return;
      }
      const firstEl = tabbables[0] as HTMLElement;
      const lastEl = tabbables[tabbables.length - 1] as HTMLElement;
      const current = document.activeElement;
      if (event.shiftKey && (current === firstEl || current === root || !root.contains(current))) {
        event.preventDefault();
        lastEl.focus();
      } else if (!event.shiftKey && (current === lastEl || !root.contains(current))) {
        event.preventDefault();
        firstEl.focus();
      }
    };
    // Keep focus inside if something outside steals it (e.g. async re-render).
    const onFocusIn = (event: FocusEvent) => {
      if (event.target instanceof Node && !root.contains(event.target)) {
        (getTabbables(root)[0] ?? root).focus();
      }
    };
    document.addEventListener("keydown", onKeyDown, true);
    document.addEventListener("focusin", onFocusIn);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      document.removeEventListener("focusin", onFocusIn);
      if (returnFocus && previous?.isConnected) previous.focus();
    };
  }, [active, ref, returnFocus]);
}

// Escape handling: a module-level stack so only the topmost overlay closes.
const escapeStack: Array<() => void> = [];
let escapeBound = false;

function onDocKeyDown(event: KeyboardEvent) {
  if (event.key !== "Escape" || event.defaultPrevented || event.isComposing) return;
  const top = escapeStack[escapeStack.length - 1];
  if (!top) return;
  event.preventDefault();
  event.stopPropagation();
  top();
}

export function useEscape(onEscape: () => void, active = true): void {
  const handlerRef = useRef(onEscape);
  handlerRef.current = onEscape;
  useEffect(() => {
    if (!active) return;
    const fn = () => handlerRef.current();
    escapeStack.push(fn);
    if (!escapeBound) {
      document.addEventListener("keydown", onDocKeyDown);
      escapeBound = true;
    }
    return () => {
      const i = escapeStack.lastIndexOf(fn);
      if (i >= 0) escapeStack.splice(i, 1);
      if (escapeStack.length === 0 && escapeBound) {
        document.removeEventListener("keydown", onDocKeyDown);
        escapeBound = false;
      }
    };
  }, [active]);
}

/** Capture the focused element now; `restore()` later returns focus to it (falls back to `fallback`). */
export function useRestoreFocus(): {
  capture: () => void;
  restore: (fallback?: HTMLElement | null) => void;
} {
  const saved = useRef<HTMLElement | null>(null);
  const capture = useCallback(() => {
    saved.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  }, []);
  const restore = useCallback((fallback?: HTMLElement | null) => {
    const target = saved.current?.isConnected ? saved.current : fallback;
    saved.current = null;
    target?.focus();
  }, []);
  return { capture, restore };
}
