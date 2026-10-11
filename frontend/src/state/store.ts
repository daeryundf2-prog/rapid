/**
 * The application store: one zustand store composed of slices.
 *
 *   route      — derived from the hash (router.ts); write via navigate/patchRoute
 *   selection  — focusedRowKey, selectedRowKeys (grid)
 *   viewer     — ViewerTarget (contracts/viewer.ts) mirrored into `row=`/`mode=`
 *   prefs      — theme, density, panel layout (persisted)
 *   overlays   — palette / help / run dialog / viewer drawer
 *   runs       — GET /api/runs with progress (status bar, command context)
 *
 * Other streams should use the hooks in ./hooks.ts rather than the raw store.
 */

import { create } from "zustand";
import { onHashChange } from "../router";
import { createOverlaySlice, type OverlaySlice } from "./slices/overlays";
import { createPrefsSlice, type PrefsSlice } from "./slices/prefs";
import { createRouteSlice, type RouteSlice } from "./slices/route";
import { createRunsSlice, type RunsSlice } from "./slices/runs";
import { createSelectionSlice, type SelectionSlice } from "./slices/selection";
import { createViewerSlice, type ViewerSlice } from "./slices/viewer";

export type AppState = RouteSlice & SelectionSlice & ViewerSlice & PrefsSlice & OverlaySlice & RunsSlice;

export const useAppStore = create<AppState>()((...a) => ({
  ...createRouteSlice(...a),
  ...createSelectionSlice(...a),
  ...createViewerSlice(...a),
  ...createPrefsSlice(...a),
  ...createOverlaySlice(...a),
  ...createRunsSlice(...a),
}));

// The hash is the source of truth: follow back/forward and manual edits for the
// lifetime of the page (one listener, attached when the store module loads).
if (typeof window !== "undefined") {
  onHashChange((route) => useAppStore.getState().syncRouteFromLocation(route));
}

const INITIAL_STATE = useAppStore.getState();

/** Tests: restore the initial data (actions are kept). */
export function resetAppStore(overrides: Partial<AppState> = {}): void {
  useAppStore.setState({ ...INITIAL_STATE, ...overrides }, true);
}
