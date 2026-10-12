import { create } from "zustand";
import { pushToast } from "../../components/toastStore";

export type CaseDialogName = "run" | "import" | "picker" | "doctor" | "report" | "delete";

interface CaseDialogState {
  open: CaseDialogName | null;
  /** run id the delete confirmation applies to. */
  deleteRunId: string | null;
  notice: string;
  noticeAssertive: boolean;
  openDialog: (name: CaseDialogName) => void;
  confirmDelete: (runId: string) => void;
  close: () => void;
  setNotice: (message: string, assertive?: boolean) => void;
}

export const useCaseDialogs = create<CaseDialogState>((set) => ({
  open: null,
  deleteRunId: null,
  notice: "",
  noticeAssertive: false,
  openDialog: (name) => set({ open: name }),
  confirmDelete: (runId) => set({ open: "delete", deleteRunId: runId }),
  close: () => set({ open: null, deleteRunId: null }),
  setNotice: (notice, assertive = false) => {
    set({ notice, noticeAssertive: assertive });
    // Shown in the shell's toast stack (U-V7); CaseFeature announces it.
    if (notice) pushToast(notice, assertive ? "error" : "info");
  },
}));
