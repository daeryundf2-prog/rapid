import { useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { lazyView } from "../../components/LazyView";
import { registerAnalysisCommands } from "./commands";
import { useAnalyses, useAnalysisStore } from "./store";

// T-116: the run dialog (form + presets) is a lazy chunk, fetched when a dialog first opens.
const AnalysisDialog = lazyView("분석 실행", () => import("./AnalysisDialog").then((m) => m.AnalysisDialog));

/**
 * Mount ONCE in the app (next to CaseFeature): registers the analysis.* commands, keeps
 * the run's job list loaded for their disabled reasons, and hosts the run dialog.
 */
export function AnalysisFeature({ runId }: { runId: string | null }) {
  const queryClient = useQueryClient();
  useEffect(() => registerAnalysisCommands(queryClient), [queryClient]);
  useAnalyses(runId);
  const dialog = useAnalysisStore((s) => s.dialog);
  const closeDialog = useAnalysisStore((s) => s.closeDialog);
  // A dialog never outlives its case.
  useEffect(() => {
    if (runId === null) useAnalysisStore.getState().closeDialog();
  }, [runId]);
  if (!dialog || !runId) return null;
  return (
    <AnalysisDialog
      key={`${dialog.kind}:${JSON.stringify(dialog.preset ?? {})}`}
      kind={dialog.kind}
      runId={runId}
      preset={dialog.preset}
      onClose={closeDialog}
    />
  );
}
