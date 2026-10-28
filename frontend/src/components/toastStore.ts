import { create } from "zustand";

/**
 * The console's one notice surface (visual-polish U-V7): bottom-right toasts. Every producer —
 * command feedback (app `showNotice`), grid actions, case dialogs — pushes here. The store is
 * NOT a live region: producers speak through announce() (the shell's single polite/assertive
 * pair), so a toast never adds a second polite region (e2e a11y rule 9).
 */
export type ToastTone = "info" | "ok" | "warn" | "error";

/** A link / button in a toast (r7 L4: "열기" on a written file). */
export interface ToastAction {
  label: string;
  /** Opens in a new tab (a read-only file URL). */
  href?: string;
  run?: () => void;
}

export interface ToastItem {
  id: number;
  text: string;
  tone: ToastTone;
  /** Second line, e.g. the path a write went to (monospace, selectable). */
  detail?: string;
  action?: ToastAction;
  /** When the toast was pushed (Date.now()); drives the dedupe window. */
  at?: number;
}

export interface ToastOptions {
  detail?: string;
  action?: ToastAction;
}

/** At most this many toasts are stacked; the oldest goes first. */
export const TOAST_MAX = 3;
/** The same sentence pushed again within this window is not shown twice. */
export const TOAST_DEDUPE_MS = 2000;
/** Non-error toasts close themselves after this long (errors stay until closed). */
export const TOAST_MS = 6000;

interface ToastState {
  toasts: ToastItem[];
  push: (text: string, tone?: ToastTone, options?: ToastOptions) => number;
  dismiss: (id: number) => void;
  /** Close the newest toast (global Esc when no dialog is open); false when there was none. */
  dismissNewest: () => boolean;
  /** Drop error toasts (a stage change: the error belonged to the page that was left). */
  clearErrors: () => void;
  clear: () => void;
}

let seq = 0;

/** Two toasts are the same when text, tone and detail line all match. */
function sameToast(
  a: { text: string; tone: ToastTone; detail?: string },
  b: { text: string; tone: ToastTone; detail?: string },
): boolean {
  return a.text === b.text && a.tone === b.tone && (a.detail ?? "") === (b.detail ?? "");
}

export const useToastStore = create<ToastState>((set, get) => ({
  toasts: [],
  push: (text, tone = "info", options = {}) => {
    const id = ++seq;
    const clean = text.trim();
    if (!clean) return id;
    const now = Date.now();
    const item: ToastItem = { id, text: clean, tone, at: now };
    if (options.detail) item.detail = options.detail;
    if (options.action) item.action = options.action;
    const recent = get().toasts.find((t) => sameToast(t, item) && now - (t.at ?? 0) < TOAST_DEDUPE_MS);
    if (recent) return recent.id;
    set((s) => ({
      // The same toast again replaces the old copy instead of stacking one.
      toasts: [...s.toasts.filter((t) => !sameToast(t, item)), item].slice(-TOAST_MAX),
    }));
    return id;
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
  dismissNewest: () => {
    const newest = get().toasts.at(-1);
    if (!newest) return false;
    get().dismiss(newest.id);
    return true;
  },
  clearErrors: () => {
    if (get().toasts.some((t) => t.tone === "error")) {
      set((s) => ({ toasts: s.toasts.filter((t) => t.tone !== "error") }));
    }
  },
  clear: () => set({ toasts: [] }),
}));

/** Push a toast from anywhere (non-React code included). */
export function pushToast(text: string, tone: ToastTone = "info", options?: ToastOptions): number {
  return useToastStore.getState().push(text, tone, options);
}
