/**
 * The list on screen (grid or thumbnail gallery) as seen by shell commands that act on "the
 * selection, else the viewer row" (AXIOM E3 tag propagation, digit tag keys). A mounted list
 * registers itself; the most recently mounted one wins and unregisters on unmount. Shell commands
 * therefore work in every view that shows rows, not only while the column grid is mounted.
 */

import type { GridRow } from "../../contracts/collection";

export interface RowSource {
  getSelectedRows: () => GridRow[];
  /** Optimistic row patch on the list's own cache; returns the rollback. */
  patchRows?: (keys: string[], patch: (row: GridRow) => GridRow) => () => void;
  refetch?: () => void;
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
