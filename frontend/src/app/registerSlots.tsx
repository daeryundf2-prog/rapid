/**
 * Slot registrations — the single integration point between the shell and the
 * feature streams: tree + case dialogs (S4), grid (S3, via gridBridge) and
 * viewer (S2, via viewerBridge).
 */

import { useEffect } from "react";
import { CommandButton } from "../commands/CommandButton";
import { AnalysisProgressChip } from "../features/analysis/AnalysisProgressChip";
import { useCaseDialogs } from "../features/case/dialogs";
import { stageOf } from "../router";
import { registerSlot, type SlotProps } from "../shell/slots";
import { useAppStore } from "../state/store";
import { connectGridToShell } from "./gridBridge";
import { IntakePane } from "./IntakePane";
// T-116: every pane is a lazy chunk; the case list (Landing) needs none of them.
import {
  AnalysisPane,
  DerivedPane,
  EvidenceTree,
  ExploreGrid,
  ProcessPage,
  ProcessPanel,
  RegistryExplorer,
  ReportPage,
  ReportPanel,
  ReviewPanel,
  Viewer,
} from "./lazyViews";
import { connectViewerToShell } from "./viewerBridge";

/** S4 tree for the routed case; an explicit empty state otherwise. */
function TreeSlot() {
  // Only what picks the panel: a new `row=` (each J/K in the grid) must not re-render the tree.
  const runId = useAppStore((s) => s.route.runId);
  const stage = useAppStore((s) => (s.route.runId ? stageOf(s.route) : null));
  if (runId) {
    switch (stage) {
      case "process":
        return <ProcessPanel />;
      case "review":
        return <ReviewPanel />;
      case "report":
        return <ReportPanel />;
      default:
        // 접수 and 탐색: the domain tree (증거 소스 first).
        return <EvidenceTree runId={runId} />;
    }
  }
  return (
    <div className="pane-empty-block">
      <p className="pane-empty">열린 케이스가 없습니다.</p>
      <CommandButton command="case.create" label="케이스 만들기…" />
      <CommandButton command="case.switch" label="케이스 열기…" />
      <CommandButton command="case.run-dialog" />
    </div>
  );
}

/** 접수 shows the case summary; every other collection is the one DataGrid. */
function GridSlot() {
  // Only the routed collection picks the pane (a new `row=` must not re-render it).
  const collection = useAppStore((s) => (s.route.runId ? s.route.collection : undefined));
  // 분석 작업 nodes: header + history + the one DataGrid over the selected job's rows.
  if (collection === "analysis") return <AnalysisPane />;
  // 통합 보기 (axiom-adoption §3.2): derived tables + original rows, not the DataGrid.
  if (collection === "derived") return <DerivedPane />;
  // 레지스트리 탐색기 (r4 §2.2): hive → key tree + value table, its own pane.
  if (collection === "registry") return <RegistryExplorer />;
  if (collection === "process") return <ProcessPage />;
  if (collection === "outputs") return <ReportPage />;
  if (collection === "intake") return <IntakePane />;
  return <ExploreGrid />;
}

/** "실행/불러오기" opens S4's run dialog (hosted by CaseFeature). */
function RunDialogBridge({ open, onClose }: SlotProps["run-dialog"]) {
  useEffect(() => {
    if (!open) return;
    useCaseDialogs.getState().openDialog("run");
    onClose();
  }, [open, onClose]);
  return null;
}

let registered = false;

export function registerAppSlots(): void {
  if (registered) return;
  registered = true;
  registerSlot("tree", TreeSlot);
  registerSlot("grid", GridSlot);
  connectGridToShell();
  registerSlot("viewer", Viewer);
  connectViewerToShell();
  registerSlot("run-dialog", RunDialogBridge);
  registerSlot("status-extra", AnalysisProgressChip);
}
