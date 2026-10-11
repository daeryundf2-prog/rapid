/**
 * Shell ⇄ viewer wiring (S1 ⇄ S2).
 *
 * The viewer keeps a small local store behind features/viewer/adapter.ts (its
 * tests drive it directly). This bridge makes the S1 store the source of
 * truth in the app: the routed target and `mode=` flow into the viewer, the
 * viewer's own history (Alt ←/→) and tab choices flow back into the URL, and
 * every "open the viewer" request (Enter) reaches the viewer's focus logic.
 * Each write is guarded by an equality check, so the subscriptions cannot loop.
 */

import { encodeRowRef } from "../contracts/rowRef";
import type { ViewerTarget } from "../contracts/viewer";
import {
  getViewerRouteMode,
  getViewerTarget,
  requestViewerFocus,
  setViewerRouteMode,
  setViewerTarget,
  subscribeViewerAdapter,
} from "../features/viewer/adapter";
import { isRestoredTarget } from "../state/slices/route";
import { useAppStore } from "../state/store";

export function viewerTargetKey(target: ViewerTarget | null): string {
  if (!target) return "";
  const highlight = target.highlight ? JSON.stringify(target.highlight) : "";
  return [
    target.runId,
    encodeRowRef(target.ref),
    target.sourcePath ?? "",
    target.preferredMode ?? "",
    highlight,
  ].join("|");
}

/** How long a URL-restored row waits for the grid to resolve it before the viewer shows it as is. */
export const RESTORE_WAIT_MS = 1500;
let restoreTimer: ReturnType<typeof setTimeout> | null = null;
let lastRow: unknown = null;

function clearRestoreTimer(): void {
  if (restoreTimer) clearTimeout(restoreTimer);
  restoreTimer = null;
}

function pushShellToViewer(force = false): void {
  const { route, viewerTarget, viewerRow } = useAppStore.getState();
  // Mode first, then target: the viewer restores `mode=` for the first target it receives.
  setViewerRouteMode(route.row ? route.mode : undefined);
  const current = getViewerTarget();
  if (viewerTargetKey(current) === viewerTargetKey(viewerTarget)) {
    clearRestoreTimer();
    // Same target, fresher grid row (e.g. review status changed): refresh the 레코드 context.
    if (current && viewerRow && viewerRow !== lastRow) {
      lastRow = viewerRow;
      setViewerTarget(current, viewerRow);
    }
    return;
  }
  // A target rebuilt from the URL lacks sourcePath; give the grid a moment to publish the
  // resolved row so the viewer's first target is the real one and `mode=` is restored on it.
  if (!force && current === null && isRestoredTarget(viewerTarget)) {
    if (!restoreTimer) {
      restoreTimer = setTimeout(() => {
        restoreTimer = null;
        pushShellToViewer(true);
      }, RESTORE_WAIT_MS);
    }
    return;
  }
  clearRestoreTimer();
  lastRow = viewerRow;
  setViewerTarget(viewerTarget, viewerRow);
}

/** Install the bridge; returns the disconnect function. */
export function connectViewerToShell(): () => void {
  pushShellToViewer();
  let lastTarget = getViewerTarget();
  let lastMode = getViewerRouteMode();

  const offApp = useAppStore.subscribe((state, prev) => {
    if (
      state.viewerTarget !== prev.viewerTarget ||
      state.viewerRow !== prev.viewerRow ||
      state.route !== prev.route
    ) {
      pushShellToViewer();
    }
    if (state.viewerFocusSeq !== prev.viewerFocusSeq) requestViewerFocus();
  });

  const offViewer = subscribeViewerAdapter(() => {
    const app = useAppStore.getState();
    const target = getViewerTarget();
    if (target !== lastTarget) {
      lastTarget = target;
      if (viewerTargetKey(target) !== viewerTargetKey(app.viewerTarget)) app.setViewerTarget(target);
    }
    const mode = getViewerRouteMode();
    if (mode !== lastMode) {
      lastMode = mode;
      const current = useAppStore.getState();
      if (current.route.row && current.route.mode !== mode) current.setViewerMode(mode);
    }
  });

  return () => {
    clearRestoreTimer();
    offApp();
    offViewer();
  };
}
