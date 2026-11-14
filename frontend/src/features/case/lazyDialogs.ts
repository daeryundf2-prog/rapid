/**
 * Case dialogs loaded on demand (T-116): opened from a command, never on the first screen, so each
 * is a lazy chunk ("… 불러오는 중", role=status; a failed chunk shows a Korean 다시 시도 message —
 * `lazyView`). CaseFeature imports them from here, never from the dialog modules.
 */

import { lazyView } from "../../components/LazyView";

export const RunDialog = lazyView("실행", () => import("./RunDialog").then((m) => m.RunDialog));
export const ImportDialog = lazyView("불러오기", () => import("./ImportDialog").then((m) => m.ImportDialog));
export const DoctorDialog = lazyView("환경 점검", () => import("./DoctorDialog").then((m) => m.DoctorDialog));
export const ReportDialog = lazyView("보고서", () => import("./ReportDialog").then((m) => m.ReportDialog));
export const CaseWizard = lazyView("케이스 만들기", () => import("./CaseWizard").then((m) => m.CaseWizard));
export const LinkCaseDialog = lazyView("케이스 연결", () =>
  import("./CaseDialogs").then((m) => m.LinkCaseDialog),
);
export const CaseEditDialog = lazyView("케이스 정보", () =>
  import("./CaseDialogs").then((m) => m.CaseEditDialog),
);
export const AddEvidenceDialog = lazyView("증거 추가", () =>
  import("./CaseDialogs").then((m) => m.AddEvidenceDialog),
);
export const AddRunDialog = lazyView("처리 추가", () => import("./CaseDialogs").then((m) => m.AddRunDialog));
export const ProblemsDialog = lazyView("문제 목록", () =>
  import("./CaseDialogs").then((m) => m.ProblemsDialog),
);
