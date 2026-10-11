import type { StateCreator } from "zustand";
import type { AppState } from "../store";

export type OverlayName = "palette" | "help" | "runDialog" | "viewerDrawer";

type OverlayFlag = "paletteOpen" | "helpOpen" | "runDialogOpen" | "viewerDrawerOpen";

export interface OverlaySlice {
  paletteOpen: boolean;
  helpOpen: boolean;
  runDialogOpen: boolean;
  /** Below 1200 px the viewer is an overlay drawer; this is its open state. */
  viewerDrawerOpen: boolean;
  /** True while the layout renders the viewer as a drawer (< 1200 px). */
  viewerIsDrawer: boolean;
  /** Last command feedback (disabled reason / failure) shown in the status bar. */
  notice: { text: string; tone: "info" | "error"; at: number } | null;
  showNotice: (text: string, tone?: "info" | "error") => void;
  clearNotice: () => void;
  setOverlay: (name: OverlayName, open: boolean) => void;
  setViewerIsDrawer: (drawer: boolean) => void;
  /** Close the topmost overlay; returns false when nothing was open. */
  closeTopOverlay: () => boolean;
}

const FLAG: Record<OverlayName, OverlayFlag> = {
  palette: "paletteOpen",
  help: "helpOpen",
  runDialog: "runDialogOpen",
  viewerDrawer: "viewerDrawerOpen",
};

/** Topmost first. */
const STACK: readonly OverlayName[] = ["palette", "help", "runDialog", "viewerDrawer"];

export function topOverlay(state: Pick<AppState, OverlayFlag>): OverlayName | null {
  return STACK.find((name) => state[FLAG[name]]) ?? null;
}

export const createOverlaySlice: StateCreator<AppState, [], [], OverlaySlice> = (set, get) => ({
  paletteOpen: false,
  helpOpen: false,
  runDialogOpen: false,
  viewerDrawerOpen: false,
  viewerIsDrawer: false,
  notice: null,
  showNotice: (text, tone = "info") => set({ notice: { text, tone, at: Date.now() } }),
  clearNotice: () => set({ notice: null }),
  setOverlay: (name, open) => {
    const flag = FLAG[name];
    const patch: Partial<Record<OverlayFlag, boolean>> = { [flag]: open };
    set(patch);
  },
  setViewerIsDrawer: (drawer) =>
    set(drawer ? { viewerIsDrawer: true } : { viewerIsDrawer: false, viewerDrawerOpen: false }),
  closeTopOverlay: () => {
    const top = topOverlay(get());
    if (!top) return false;
    get().setOverlay(top, false);
    return true;
  },
});
