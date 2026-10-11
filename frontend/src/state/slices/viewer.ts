import type { StateCreator } from "zustand";
import type { GridRow } from "../../contracts/collection";
import { encodeRowRef } from "../../contracts/rowRef";
import type { ViewerMode, ViewerTarget } from "../../contracts/viewer";
import type { AppState } from "../store";

export interface ViewerTargetOptions {
  /** Full grid row for the target (S3 `focusedRow`). */
  row?: GridRow | null;
  /**
   * false = an automatic selection (first row focused on open): the viewer
   * loads it but `row=` is not written, so `#/case/x/files` stays canonical.
   * Default true.
   */
  syncUrl?: boolean;
}

export interface ViewerSlice {
  /** What the always-open viewer shows (contracts/viewer.ts). */
  viewerTarget: ViewerTarget | null;
  /**
   * Publish the row the viewer should follow. Mirrors `row=` into the URL
   * (history replace, so J/K does not flood back/forward). The URL `mode=`
   * is kept when the row is unchanged, cleared otherwise so the viewer
   * auto-selects the best mode for the new row.
   */
  setViewerTarget: (target: ViewerTarget | null, options?: ViewerTargetOptions) => void;
  /** The grid row behind `viewerTarget` when the grid published it (viewer 레코드 section, review keys). */
  viewerRow: GridRow | null;
  /** Viewer mode chosen by the user or auto-selected; mirrored into `mode=`. */
  setViewerMode: (mode: ViewerMode | undefined) => void;
  /** Increments on every "open the viewer" request (Enter); the viewer focuses its selected tab. */
  viewerFocusSeq: number;
  requestViewerFocus: () => void;
}

export const createViewerSlice: StateCreator<AppState, [], [], ViewerSlice> = (set, get) => ({
  viewerTarget: null,
  viewerRow: null,
  viewerFocusSeq: 0,
  requestViewerFocus: () => set({ viewerFocusSeq: get().viewerFocusSeq + 1 }),
  setViewerTarget: (target, options = {}) => {
    const { route, patchRoute } = get();
    const row =
      target && options.row && encodeRowRef(options.row.ref) === encodeRowRef(target.ref)
        ? options.row
        : null;
    if (options.syncUrl === false) {
      // Drop a stale `row=` (it names another row) before publishing; never add one.
      if (route.row && (!target || encodeRowRef(route.row) !== encodeRowRef(target.ref))) {
        patchRoute({ row: undefined, mode: undefined }, { replace: true });
      }
      set({ viewerTarget: target, viewerRow: row });
      return;
    }
    set({ viewerTarget: target, viewerRow: row });
    if (!target) {
      if (route.row) patchRoute({ row: undefined, mode: undefined }, { replace: true });
      return;
    }
    const sameRow = route.row ? encodeRowRef(route.row) === encodeRowRef(target.ref) : false;
    if (!sameRow) patchRoute({ row: target.ref, mode: undefined }, { replace: true });
  },
  setViewerMode: (mode) => {
    const { route, patchRoute } = get();
    if (!route.row || route.mode === mode) return;
    patchRoute({ mode }, { replace: true });
  },
});
