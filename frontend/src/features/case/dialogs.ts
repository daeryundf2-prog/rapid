import { create } from "zustand";
import { pushToast } from "../../components/toastStore";
import type { ExportKind } from "./exports";

export type CaseDialogName =
  | "run"
  | "import"
  | "picker"
  | "doctor"
  | "report"
  | "delete"
  // Case intake (AXIOM adoption E1).
  | "create"
  | "link"
  | "case-edit"
  | "evidence-add"
  | "run-add"
  | "problems";

/** What a case-intake dialog acts on (case / evidence / run problems reason). */
export interface CaseDialogTarget {
  caseId?: string;
  evidenceCitationId?: string;
  runId?: string;
  reasonId?: string;
  reasonLabel?: string;
  /** 보고서 내보내기: the kind chosen when the dialog opens. */
  exportKind?: ExportKind;
}

interface CaseDialogState {
  open: CaseDialogName | null;
  /** run id the delete confirmation applies to. */
  deleteRunId: string | null;
  target: CaseDialogTarget;
  notice: string;
  noticeAssertive: boolean;
  openDialog: (name: CaseDialogName, target?: CaseDialogTarget) => void;
  confirmDelete: (runId: string) => void;
  close: () => void;
  setNotice: (message: string, assertive?: boolean) => void;
}

export const useCaseDialogs = create<CaseDialogState>((set) => ({
  open: null,
  deleteRunId: null,
  target: {},
  notice: "",
  noticeAssertive: false,
  openDialog: (name, target = {}) => set({ open: name, target }),
  confirmDelete: (runId) => set({ open: "delete", deleteRunId: runId }),
  close: () => set({ open: null, deleteRunId: null, target: {} }),
  setNotice: (notice, assertive = false) => {
    set({ notice, noticeAssertive: assertive });
    // Shown in the shell's toast stack (U-V7); CaseFeature announces it.
    if (notice) pushToast(notice, assertive ? "error" : "info");
  },
}));
