import { create } from "zustand";

/**
 * The console's one notice surface (visual-polish U-V7): bottom-right toasts. Every producer —
 * command feedback (app `showNotice`), grid actions, case dialogs — pushes here. The store is
 * NOT a live region: producers speak through announce() (the shell's single polite/assertive
 * pair), so a toast never adds a second polite region (e2e a11y rule 9).
 */
export type ToastTone = "info" | "ok" | "warn" | "error";

export interface ToastItem {
  id: number;
  text: string;
  tone: ToastTone;
}

/** At most this many toasts are stacked; the oldest goes first. */
export const TOAST_MAX = 3;
/** Non-error toasts close themselves after this long (errors stay until closed). */
export const TOAST_MS = 6000;

interface ToastState {
  toasts: ToastItem[];
  push: (text: string, tone?: ToastTone) => number;
  dismiss: (id: number) => void;
  clear: () => void;
}

let seq = 0;

export const useToastStore = create<ToastState>((set) => ({
  toasts: [],
  push: (text, tone = "info") => {
    const id = ++seq;
    const clean = text.trim();
    if (!clean) return id;
    set((s) => ({
      // The same sentence again replaces the old toast instead of stacking a copy.
      toasts: [...s.toasts.filter((t) => t.text !== clean), { id, text: clean, tone }].slice(-TOAST_MAX),
    }));
    return id;
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
  clear: () => set({ toasts: [] }),
}));

/** Push a toast from anywhere (non-React code included). */
export function pushToast(text: string, tone: ToastTone = "info"): number {
  return useToastStore.getState().push(text, tone);
}
