/**
 * 통합 보기 state shared by the pane and the `derived.*` commands: the selected value, the pane's
 * "load more" hook, a running rebuild, and the origin of rows opened from the pane (citations add
 * `통합:<표>/<정규화 값>` while the viewer shows such a row).
 */

import { create } from "zustand";
import type { RowRef } from "../../contracts/rowRef";
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

interface DerivedState {
  selected: DerivedSelection | null;
  /** The pane's next-page loader (null when the pane is closed or no page follows). */
  loadMore: (() => void) | null;
  /** Focus the original-rows panel (set by the mounted pane). */
  focusRows: (() => void) | null;
  /** `analysis_id` of a rebuild this console started and has not seen finish. */
  rebuilding: string | null;
  origins: Record<string, DerivedOrigin>;
  select: (selection: DerivedSelection | null) => void;
  setLoadMore: (loader: (() => void) | null) => void;
  setFocusRows: (focus: (() => void) | null) => void;
  setRebuilding: (analysisId: string | null) => void;
  rememberOrigin: (runId: string, ref: RowRef, origin: DerivedOrigin) => void;
}

/** Origins kept (rows opened from the pane); the oldest are forgotten first. */
export const MAX_ORIGINS = 50;

export function originKey(runId: string, ref: Pick<RowRef, "collection" | "kind" | "locator">): string {
  return [runId, ref.collection, ref.kind ?? "", ref.locator].join("|");
}

export const useDerivedStore = create<DerivedState>()((set) => ({
  selected: null,
  loadMore: null,
  focusRows: null,
  rebuilding: null,
  origins: {},
  select: (selected) => set({ selected }),
  setLoadMore: (loadMore) => set({ loadMore }),
  setFocusRows: (focusRows) => set({ focusRows }),
  setRebuilding: (rebuilding) => set({ rebuilding }),
  rememberOrigin: (runId, ref, origin) =>
    set((state) => {
      const key = originKey(runId, ref);
      const entries = Object.entries(state.origins).filter(([existing]) => existing !== key);
      entries.push([key, origin]);
      return { origins: Object.fromEntries(entries.slice(-MAX_ORIGINS)) };
    }),
}));

/** The 통합 보기 value a viewer row was opened from, if any. */
export function derivedOriginOf(
  runId: string,
  ref: Pick<RowRef, "collection" | "kind" | "locator">,
): DerivedOrigin | undefined {
  return useDerivedStore.getState().origins[originKey(runId, ref)];
}
