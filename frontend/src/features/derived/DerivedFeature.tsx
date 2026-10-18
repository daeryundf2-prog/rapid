import { useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { isAnalysisActive } from "../../api/analyses";
import { useAnalyses } from "../analysis/store";
import { derivedMetaKey } from "./api";
import { registerDerivedCommands } from "./commands";
import { useDerivedStore } from "./store";

/**
 * Mount ONCE in the app (next to AnalysisFeature): registers the derived.* commands and, when a
 * 통합 보기 rebuild this console started settles, refreshes the tables, the tree and the pane.
 */
export function DerivedFeature({ runId }: { runId: string | null }) {
  const queryClient = useQueryClient();
  useEffect(() => registerDerivedCommands(queryClient), [queryClient]);
  const rebuilding = useDerivedStore((s) => s.rebuilding);
  const { analyses } = useAnalyses(rebuilding ? runId : null);
  useEffect(() => {
    if (!rebuilding || !runId) return;
    const job = analyses.find((item) => item.analysis_id === rebuilding);
    if (!job || isAnalysisActive(job)) return;
    useDerivedStore.getState().setRebuilding(null);
    void queryClient.invalidateQueries({ queryKey: derivedMetaKey(runId) });
    void queryClient.invalidateQueries({ queryKey: ["derived-page", runId] });
    void queryClient.invalidateQueries({ queryKey: ["derived-rows", runId] });
    void queryClient.invalidateQueries({ queryKey: ["run-tree", runId] });
  }, [rebuilding, runId, analyses, queryClient]);
  // A rebuild belongs to its case.
  useEffect(() => {
    if (runId === null) useDerivedStore.getState().setRebuilding(null);
  }, [runId]);
  return null;
}
