import { create } from "zustand";
import type { ItemRow, TreeNode } from "../api/runs";

export type Theme = "dark" | "light";

const THEME_KEY = "rapidtriage.v2.theme";

function readStoredTheme(): Theme | null {
  try {
    const stored = window.localStorage.getItem(THEME_KEY);
    return stored === "dark" || stored === "light" ? stored : null;
  } catch {
    return null;
  }
}

function applyThemeAttribute(theme: Theme | null): void {
  if (theme) {
    document.documentElement.dataset.theme = theme;
  } else {
    delete document.documentElement.dataset.theme;
  }
}

interface UiState {
  /** Explicit user choice; null means "follow prefers-color-scheme". */
  theme: Theme | null;
  selectedRunId: string | null;
  /** Selected evidence-tree node; null means the run list is shown. */
  selectedNode: TreeNode | null;
  /** Selected item row in the center table (shown in the detail pane). */
  selectedItem: ItemRow | null;
  /** Header search text; filters the center table client-side. */
  tableFilter: string;
  setTheme: (theme: Theme | null) => void;
  toggleTheme: () => void;
  selectRun: (runId: string | null) => void;
  selectNode: (node: TreeNode | null) => void;
  selectItem: (item: ItemRow | null) => void;
  setTableFilter: (value: string) => void;
}

export const useUiStore = create<UiState>((set, get) => ({
  theme: readStoredTheme(),
  selectedRunId: null,
  setTheme: (theme) => {
    try {
      if (theme) {
        window.localStorage.setItem(THEME_KEY, theme);
      } else {
        window.localStorage.removeItem(THEME_KEY);
      }
    } catch {
      // Storage may be disabled; theme simply won't persist.
    }
    applyThemeAttribute(theme);
    set({ theme });
  },
  toggleTheme: () => {
    const current = get().theme ?? systemTheme();
    get().setTheme(current === "dark" ? "light" : "dark");
  },
  selectedNode: null,
  selectedItem: null,
  selectRun: (runId) => set({ selectedRunId: runId, selectedNode: null, selectedItem: null }),
  selectNode: (node) => set({ selectedNode: node, selectedItem: null }),
  selectItem: (item) => set({ selectedItem: item }),
  tableFilter: "",
  setTableFilter: (value) => set({ tableFilter: value }),
}));

export function systemTheme(): Theme {
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

/** Apply the persisted theme before first paint-related work. */
export function initTheme(): void {
  applyThemeAttribute(readStoredTheme());
}
