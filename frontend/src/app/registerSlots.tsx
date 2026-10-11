/**
 * Slot registrations — the single integration point between the shell and the
 * feature streams: tree + case dialogs (S4), grid (S3, via gridBridge) and
 * viewer (S2, via viewerBridge).
 */

import { useEffect } from "react";
import { CommandButton } from "../commands/CommandButton";
import { useCaseDialogs } from "../features/case/dialogs";
import { DataGrid } from "../features/grid/DataGrid";
import { EvidenceTree } from "../features/tree/EvidenceTree";
import { Viewer } from "../features/viewer/Viewer";
import { registerSlot, type SlotProps } from "../shell/slots";
import { useRoute } from "../state/hooks";
import { connectGridToShell } from "./gridBridge";
import { IntakePane } from "./IntakePane";
import { ViewSwitch } from "./ViewSwitch";
import { connectViewerToShell } from "./viewerBridge";

/** S4 tree for the routed case; an explicit empty state otherwise. */
function TreeSlot() {
  const { route } = useRoute();
  if (route.runId) return <EvidenceTree runId={route.runId} />;
  return (
    <div className="pane-empty-block">
      <p className="pane-empty">열린 케이스가 없습니다.</p>
      <CommandButton command="case.switch" label="케이스 열기…" />
      <CommandButton command="case.run-dialog" />
    </div>
  );
}

/** 접수 shows the case summary; every other collection is the one DataGrid. */
function GridSlot() {
  const { route } = useRoute();
  return route.runId && route.collection === "intake" ? (
    <IntakePane />
  ) : (
    <ViewSwitch>
      <DataGrid />
    </ViewSwitch>
  );
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
}
