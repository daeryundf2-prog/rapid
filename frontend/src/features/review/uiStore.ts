/**
 * Open/closed state of the review-tool dialogs (AXIOM E3): 태그 관리 and 메모·이력. One
 * host (ReviewToolsHost) renders them; commands only flip this store.
 */

import { create } from "zustand";
import type { GridRow } from "../../contracts/collection";

export interface NotePanelTarget {
  runId: string;
  row: GridRow;
}

interface ReviewToolsUi {
  tagManagerRunId: string | null;
  noteTarget: NotePanelTarget | null;
  openTagManager: (runId: string) => void;
  closeTagManager: () => void;
  openNotePanel: (target: NotePanelTarget) => void;
  closeNotePanel: () => void;
}

export const useReviewToolsUi = create<ReviewToolsUi>((set) => ({
  tagManagerRunId: null,
  noteTarget: null,
  openTagManager: (runId) => set({ tagManagerRunId: runId }),
  closeTagManager: () => set({ tagManagerRunId: null }),
  openNotePanel: (target) => set({ noteTarget: target }),
  closeNotePanel: () => set({ noteTarget: null }),
}));
