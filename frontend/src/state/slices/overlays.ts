import type { StateCreator } from "zustand";
import { pushToast } from "../../components/toastStore";
import type { AppState } from "../store";

/**
 * Wide-layout viewer pane on 탐색·검토 (visual-polish S4 follow-up): "auto" collapses it to the
 * 36px rail while no row is selected (no `row=`), "collapsed" is the analyst's 뷰어 접기 (kept for
 * the session), "open" is an explicit expand with no row selected yet.
 */
export type ViewerPaneMode = "auto" | "collapsed" | "open";
export const VIEWER_COLLAPSED_KEY = "rapidtriage.v2.viewerCollapsed";

function storedViewerPane(): ViewerPaneMode {
  try {
    return window.sessionStorage.getItem(VIEWER_COLLAPSED_KEY) === "1" ? "collapsed" : "auto";
  } catch {
    return "auto";
  }
}

function writeViewerPane(mode: ViewerPaneMode): void {
  try {
    if (mode === "collapsed") window.sessionStorage.setItem(VIEWER_COLLAPSED_KEY, "1");
    else window.sessionStorage.removeItem(VIEWER_COLLAPSED_KEY);
  } catch {
    // Session storage may be unavailable; the choice lasts until reload.
  }
}

/** The wide viewer pane is shown as its rail (never in the drawer layout). */
export function viewerPaneCollapsed(
  state: Pick<AppState, "viewerPane" | "viewerIsDrawer"> & { route: { row?: unknown } },
): boolean {
  if (state.viewerIsDrawer) return false;
  return state.viewerPane === "collapsed" || (state.viewerPane === "auto" && !state.route.row);
}

export type OverlayName = "palette" | "help" | "runDialog" | "treeDrawer" | "viewerDrawer";

type OverlayFlag = "paletteOpen" | "helpOpen" | "runDialogOpen" | "treeDrawerOpen" | "viewerDrawerOpen";

export interface OverlaySlice {
  paletteOpen: boolean;
  helpOpen: boolean;
  runDialogOpen: boolean;
  /** Below 900 px the left panel (tree) is an overlay drawer (scroll review C2); its open state. */
  treeDrawerOpen: boolean;
  /** True while the layout renders the left panel as a drawer (< 900 px). */
  treeIsDrawer: boolean;
  setTreeIsDrawer: (drawer: boolean) => void;
  /** Wide layouts: the left panel is folded to its 36px rail (dragged shut or 탐색 패널 접기). */
  treeCollapsed: boolean;
  setTreeCollapsed: (collapsed: boolean) => void;
  /** Below 1200 px the viewer is an overlay drawer; this is its open state. */
  viewerDrawerOpen: boolean;
  /** True while the layout renders the viewer as a drawer (< 1200 px). */
  viewerIsDrawer: boolean;
  /** Wide viewer pane: auto / collapsed (session) / open (see ViewerPaneMode). */
  viewerPane: ViewerPaneMode;
  setViewerPane: (mode: ViewerPaneMode) => void;
  /** Last command feedback (disabled reason / failure); shown as a toast (U-V7). */
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
  treeDrawer: "treeDrawerOpen",
  viewerDrawer: "viewerDrawerOpen",
};

/** Topmost first. */
const STACK: readonly OverlayName[] = ["palette", "help", "runDialog", "treeDrawer", "viewerDrawer"];

export function topOverlay(state: Pick<AppState, OverlayFlag>): OverlayName | null {
  return STACK.find((name) => state[FLAG[name]]) ?? null;
}

export const createOverlaySlice: StateCreator<AppState, [], [], OverlaySlice> = (set, get) => ({
  paletteOpen: false,
  helpOpen: false,
  runDialogOpen: false,
  treeDrawerOpen: false,
  treeIsDrawer: false,
  setTreeIsDrawer: (drawer) =>
    set(drawer ? { treeIsDrawer: true } : { treeIsDrawer: false, treeDrawerOpen: false }),
  treeCollapsed: false,
  setTreeCollapsed: (collapsed) => set({ treeCollapsed: collapsed }),
  viewerDrawerOpen: false,
  viewerIsDrawer: false,
  viewerPane: storedViewerPane(),
  setViewerPane: (mode) => {
    writeViewerPane(mode);
    set({ viewerPane: mode });
  },
  notice: null,
  showNotice: (text, tone = "info") => {
    set({ notice: { text, tone, at: Date.now() } });
    pushToast(text, tone);
  },
  clearNotice: () => set({ notice: null }),
  setOverlay: (name, open) => {
    const flag = FLAG[name];
    const patch: Partial<Record<OverlayFlag, boolean>> = { [flag]: open };
    // The two drawers share the narrow pane area: opening one closes the other.
    if (open && name === "treeDrawer") patch.viewerDrawerOpen = false;
    if (open && name === "viewerDrawer") patch.treeDrawerOpen = false;
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
