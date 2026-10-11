import type { StateCreator } from "zustand";
import type { CollectionId, ReviewStatus } from "../../contracts/collection";
import { encodeRowRef } from "../../contracts/rowRef";
import { collectionChanged, currentHashRoute, type Route, routesEqual, writeHash } from "../../router";
import type { AppState } from "../store";

export interface NavigateOptions {
  /** Replace the current history entry instead of pushing a new one. */
  replace?: boolean;
}

export interface OpenCollectionOptions extends NavigateOptions {
  kind?: string;
  status?: ReviewStatus;
  /** Artifact category node (`category=`, artifacts without a kind). */
  category?: string;
  q?: string;
  /** Run to open; defaults to the current run. */
  runId?: string;
}

export interface RouteSlice {
  /** Always equal to `parseHash(location.hash)` once the router is attached. */
  route: Route;
  /** Replace the whole route (writes the hash). */
  navigate: (route: Route, options?: NavigateOptions) => void;
  /** Merge into the current route (writes the hash). Keys set to `undefined` are cleared. */
  patchRoute: (patch: Partial<Route>, options?: NavigateOptions) => void;
  /** Tree/palette navigation: open a collection node, keeping the viewer row (plan U1). */
  openCollection: (collection: CollectionId, options?: OpenCollectionOptions) => void;
  /** Called by the router on back/forward/manual edits; never writes the hash. */
  syncRouteFromLocation: (route: Route) => void;
}

/** Apply a new route and its side effects on selection / viewer target. */
export function applyRoute(
  get: () => AppState,
  set: (partial: Partial<AppState>) => void,
  next: Route,
): void {
  const prev = get().route;
  if (routesEqual(prev, next)) return;
  const partial: Partial<AppState> = { route: next };
  if (collectionChanged(prev, next)) {
    partial.focusedRowKey = null;
    partial.selectedRowKeys = [];
  }
  const target = get().viewerTarget;
  if (prev.runId !== next.runId) {
    partial.viewerTarget = next.row && next.runId ? seedTarget(next) : null;
  } else if (!next.row) {
    // Only an explicit row removal (back/forward, cleared selection) empties the viewer;
    // a target that was never mirrored into the URL (auto-focused first row) survives.
    if (prev.row) partial.viewerTarget = null;
  } else if (!target || encodeRowRef(target.ref) !== encodeRowRef(next.row)) {
    partial.viewerTarget = seedTarget(next);
  }
  if ("viewerTarget" in partial) partial.viewerRow = null;
  set(partial);
}

/**
 * A target restored from the URL (refresh / back / shared link) only knows the
 * RowRef: the grid replaces it with the full row (sourcePath etc.) once it
 * resolves `route.row`, and the viewer may resolve metadata from the locator.
 */
const restoredTargets = new WeakSet<object>();

/** True for a target rebuilt from the URL that the grid has not resolved yet (no sourcePath). */
export function isRestoredTarget(target: AppState["viewerTarget"]): boolean {
  return target !== null && restoredTargets.has(target);
}

function seedTarget(route: Route): AppState["viewerTarget"] {
  if (!route.row || !route.runId) return null;
  const target = { ref: route.row, runId: route.runId, sourcePath: null, preferredMode: route.mode };
  restoredTargets.add(target);
  return target;
}

export const createRouteSlice: StateCreator<AppState, [], [], RouteSlice> = (set, get) => ({
  route: currentHashRoute(),
  navigate: (route, options) => {
    writeHash(route, options?.replace ?? false);
    applyRoute(get, set, route);
  },
  patchRoute: (patch, options) => {
    const merged: Route = { ...get().route, ...patch };
    for (const key of Object.keys(patch) as Array<keyof Route>) {
      if (patch[key] === undefined) delete merged[key];
    }
    get().navigate(merged, options);
  },
  openCollection: (collection, options = {}) => {
    const current = get().route;
    const runId = options.runId ?? current.runId;
    if (!runId) return;
    const sameRun = runId === current.runId;
    const next: Route = { runId, collection };
    if (collection === "artifacts" && options.kind) next.kind = options.kind;
    else if (collection === "artifacts" && options.category) next.category = options.category;
    if (collection === "review" && options.status) next.status = options.status;
    if (options.q) next.q = options.q;
    if (sameRun && current.row) {
      next.row = current.row;
      if (current.mode) next.mode = current.mode;
    }
    get().navigate(next, options);
  },
  syncRouteFromLocation: (route) => applyRoute(get, set, route),
});
