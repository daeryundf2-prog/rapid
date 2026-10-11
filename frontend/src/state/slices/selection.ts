import type { StateCreator } from "zustand";
import type { RowRef } from "../../contracts/rowRef";
import type { AppState } from "../store";

/** Canonical grid row key (contracts/collection.ts GridRow.rowKey): `${collection}[:${kind}]:${locator}`. */
export function rowKeyOf(ref: RowRef): string {
  return ref.kind ? `${ref.collection}:${ref.kind}:${ref.locator}` : `${ref.collection}:${ref.locator}`;
}

export interface SelectionSlice {
  /** Row with the roving focus in the grid (J/K moves it). */
  focusedRowKey: string | null;
  /** Rows checked for batch actions (Space toggles). */
  selectedRowKeys: string[];
  focusRow: (rowKey: string | null) => void;
  setSelectedRows: (rowKeys: string[]) => void;
  toggleRowSelected: (rowKey: string) => void;
  clearSelection: () => void;
}

export const createSelectionSlice: StateCreator<AppState, [], [], SelectionSlice> = (set, get) => ({
  focusedRowKey: null,
  selectedRowKeys: [],
  focusRow: (rowKey) => set({ focusedRowKey: rowKey }),
  setSelectedRows: (rowKeys) => set({ selectedRowKeys: Array.from(new Set(rowKeys)) }),
  toggleRowSelected: (rowKey) => {
    const current = get().selectedRowKeys;
    set({
      selectedRowKeys: current.includes(rowKey) ? current.filter((k) => k !== rowKey) : [...current, rowKey],
    });
  },
  clearSelection: () => set({ focusedRowKey: null, selectedRowKeys: [] }),
});
