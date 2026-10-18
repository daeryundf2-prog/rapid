/**
 * 통합 보기 state shared by the pane and the `derived.*` commands: the selected value, the pane's
 * "load more" hook, a running rebuild, and the origin of the row opened from the pane (citations add
 * `통합:<표>/<정규화 값>` while the viewer shows that row).
 *
 * The origin is provenance, so it lives only as long as the path it describes: the moment the
 * examiner reaches the viewer some other way — another row (J/K, click), another family / node /
 * run, or a cleared row — it is forgotten, and coming back to the same row later cites no 통합
 * value (the row was then reached from the grid, not from 통합 보기).
 */

import { create } from "zustand";
import type { RowRef } from "../../contracts/rowRef";
import type { Route } from "../../router";
import { useAppStore } from "../../state/store";
import type { DerivedRow, DerivedTableId } from "./api";

export interface DerivedSelection {
  runId: string;
  table: DerivedTableId;
  row: DerivedRow;
}

export interface DerivedOrigin {
  table: DerivedTableId;
  normalized: string;
}

/** The one row opened from the pane, with the route it was opened into. */
export interface ActiveDerivedOrigin {
  key: string;
  origin: DerivedOrigin;
  /** `routeContext` of the family grid the row was opened in (null until the pane's navigation lands). */
  context: string | null;
}

interface DerivedState {
  selected: DerivedSelection | null;
  /** The pane's next-page loader (null when the pane is closed or no page follows). */
  loadMore: (() => void) | null;
  /** Focus the original-rows panel (set by the mounted pane). */
  focusRows: (() => void) | null;
  /** `analysis_id` of a rebuild this console started and has not seen finish. */
  rebuilding: string | null;
  /** The row opened from the pane while the viewer still shows it on the path it was opened by. */
  active: ActiveDerivedOrigin | null;
  /** The value panel shows the 연결 그래프 (r4 §2.3) instead of the original-row list. */
  graphMode: boolean;
  setGraphMode: (on: boolean) => void;
  select: (selection: DerivedSelection | null) => void;
  setLoadMore: (loader: (() => void) | null) => void;
  setFocusRows: (focus: (() => void) | null) => void;
  setRebuilding: (analysisId: string | null) => void;
  /** Called right before the pane navigates to the sample's family grid. */
  rememberOrigin: (runId: string, ref: RowRef, origin: DerivedOrigin) => void;
  clearOrigin: () => void;
}

export function originKey(runId: string, ref: Pick<RowRef, "collection" | "kind" | "locator">): string {
  return [runId, ref.collection, ref.kind ?? "", ref.locator].join("|");
}

export const useDerivedStore = create<DerivedState>()((set) => ({
  selected: null,
  loadMore: null,
  focusRows: null,
  rebuilding: null,
  active: null,
  graphMode: false,
  setGraphMode: (graphMode) => set({ graphMode }),
  select: (selected) => set({ selected }),
  setLoadMore: (loadMore) => set({ loadMore }),
  setFocusRows: (focusRows) => set({ focusRows }),
  setRebuilding: (rebuilding) => set({ rebuilding }),
  rememberOrigin: (runId, ref, origin) =>
    set({ active: { key: originKey(runId, ref), origin, context: null } }),
  clearOrigin: () => set({ active: null }),
}));

/** The grid a route shows (filters, sort and the row itself excluded). */
export function routeContext(route: Route): string {
  return [
    route.runId ?? "",
    route.collection ?? "",
    route.kind ?? "",
    route.category ?? "",
    route.analysisId ?? "",
  ].join("|");
}

/** The 통합 보기 value a viewer row was opened from, if any. */
export function derivedOriginOf(
  runId: string,
  ref: Pick<RowRef, "collection" | "kind" | "locator">,
): DerivedOrigin | undefined {
  const active = useDerivedStore.getState().active;
  return active && active.key === originKey(runId, ref) ? active.origin : undefined;
}

/**
 * Forget the origin on any navigation that is not the pane's own: the viewer showing another row
 * (or none), or the route leaving the family grid the row was opened in.
 */
export function originStillHolds(
  active: ActiveDerivedOrigin,
  route: Route,
  target: ViewerTargetLike,
): boolean {
  if (!target || originKey(target.runId, target.ref) !== active.key) return false;
  return active.context === null || active.context === routeContext(route);
}

/** Store subscription body (exported for tests): pin the arrival grid, then clear on any other path. */
export function followNavigation(route: Route, target: ViewerTargetLike): void {
  const { active, clearOrigin } = useDerivedStore.getState();
  if (!active) return;
  if (!originStillHolds(active, route, target)) clearOrigin();
  else if (active.context === null)
    useDerivedStore.setState({ active: { ...active, context: routeContext(route) } });
}

type ViewerTargetLike = { runId: string; ref: Pick<RowRef, "collection" | "kind" | "locator"> } | null;

if (typeof window !== "undefined") {
  useAppStore.subscribe((state, prev) => {
    if (state.route === prev.route && state.viewerTarget === prev.viewerTarget) return;
    followNavigation(state.route, state.viewerTarget);
  });
}
