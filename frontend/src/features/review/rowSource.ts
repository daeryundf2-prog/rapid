/**
 * The list on screen (grid or thumbnail gallery) as seen by shell commands that act on "the
 * selection, else the viewer row" (AXIOM E3 tag propagation, digit tag keys). A mounted list
 * registers itself; the most recently mounted one wins and unregisters on unmount. Shell commands
 * therefore work in every view that shows rows, not only while the column grid is mounted.
 */

import type { GridRow } from "../../contracts/collection";

/**
 * Where to move the list's focused row (verdict advance, J / K from the viewer, Z back to the
 * judged row): one step from the focused row, the row after the last of `after`, the next row
 * without a verdict (`unreviewed`), or the row with `key`. `domFocus` false keeps DOM focus where
 * it is (the viewer), true moves it onto the row.
 */
export interface RowFocusRequest {
  step?: 1 | -1;
  after?: readonly string[];
  unreviewed?: boolean;
  key?: string;
  domFocus: boolean;
}

export interface RowSource {
  getSelectedRows: () => GridRow[];
  /** The list's focused (cursor) row: the verdict scope when the viewer has no target yet. */
  getFocusedRow?: () => GridRow | undefined;
  /** Optimistic row patch on the list's own cache; returns the rollback. */
  patchRows?: (keys: string[], patch: (row: GridRow) => GridRow) => () => void;
  refetch?: () => void;
  /** Move the focused row; false when there is no such row (end of the list, none unreviewed). */
  moveFocus?: (request: RowFocusRequest) => boolean;
  clearSelection?: () => void;
}

const sources: RowSource[] = [];

export function registerRowSource(source: RowSource): () => void {
  sources.push(source);
  return () => {
    const at = sources.lastIndexOf(source);
    if (at >= 0) sources.splice(at, 1);
  };
}

export function currentRowSource(): RowSource | null {
  return sources[sources.length - 1] ?? null;
}

/** Tests. */
export function resetRowSources(): void {
  sources.length = 0;
}
