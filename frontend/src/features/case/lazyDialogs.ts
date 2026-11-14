/**
 * Case dialogs loaded on demand (T-116): opened from a command, never on the first screen, so each
 * is a lazy chunk ("… 불러오는 중", role=status; a failed chunk shows a Korean 다시 시도 message —
 * `lazyView`), both inside a modal frame with 닫기 (`lazyDialog`). CaseFeature imports them from
 * here, never from the dialog modules.
 */

import type { ComponentType } from "react";
import { type LazyViewComponent, lazyView } from "../../components/LazyView";
import { LazyDialogFrame } from "./Modal";

/** A lazy dialog: its loading status and a failed chunk render inside a modal with 닫기 (WB-12 P2-13). */
export function lazyDialog<P extends { onClose: () => void }>(
  label: string,
  load: () => Promise<ComponentType<P>>,
): LazyViewComponent<P> {
  return lazyView(label, load, { Frame: LazyDialogFrame, closeOf: (props) => props.onClose });
}

export const RunDialog = lazyDialog("실행", () => import("./RunDialog").then((m) => m.RunDialog));
export const ImportDialog = lazyDialog("불러오기", () =>
  import("./ImportDialog").then((m) => m.ImportDialog),
);
export const DoctorDialog = lazyDialog("환경 점검", () =>
  import("./DoctorDialog").then((m) => m.DoctorDialog),
);
export const ReportDialog = lazyDialog("보고서", () => import("./ReportDialog").then((m) => m.ReportDialog));
export const CaseWizard = lazyDialog("케이스 만들기", () => import("./CaseWizard").then((m) => m.CaseWizard));
export const LinkCaseDialog = lazyDialog("케이스 연결", () =>
  import("./CaseDialogs").then((m) => m.LinkCaseDialog),
);
export const CaseEditDialog = lazyDialog("케이스 정보", () =>
  import("./CaseDialogs").then((m) => m.CaseEditDialog),
);
export const AddEvidenceDialog = lazyDialog("증거 추가", () =>
  import("./CaseDialogs").then((m) => m.AddEvidenceDialog),
);
export const AddRunDialog = lazyDialog("처리 추가", () =>
  import("./CaseDialogs").then((m) => m.AddRunDialog),
);
export const ProblemsDialog = lazyDialog("문제 목록", () =>
  import("./CaseDialogs").then((m) => m.ProblemsDialog),
);
