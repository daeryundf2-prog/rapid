import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo } from "react";
import { LiveRegion } from "../a11y";
import { ApiError } from "../api/client";
import { RUNS_QUERY_KEY, useRunsPoll } from "../api/runsProgress";
import { caseOpenCommands, registerBuiltinCommands } from "../commands/builtin";
import { registerCommands } from "../commands/registry";
import { AnalysisFeature } from "../features/analysis/AnalysisFeature";
import { CaseFeature } from "../features/case/CaseFeature";
import { useReviewInvalidation } from "../features/grid/reviewMap";
import { registerStageCommands } from "../features/stages/stages";
import { Layout } from "../shell/Layout";
import { useShortcuts } from "../shortcuts";
import { useRoute } from "../state/hooks";
import { TokenGate } from "./TokenGate";

/** Shell root: commands, key map, runs poller, token gate, layout. */
export function App() {
  const queryClient = useQueryClient();
  const runsQuery = useRunsPoll();
  const { route } = useRoute();
  useShortcuts();
  useReviewInvalidation();

  useEffect(() => registerBuiltinCommands(queryClient), [queryClient]);
  useEffect(() => registerStageCommands(), []);

  // One "case.open.{id}" palette entry per run; re-register only when the run list changes.
  const runs = runsQuery.data;
  const runKey = (runs ?? []).map((r) => `${r.run_id}:${r.request?.root ?? ""}`).join("|");
  // biome-ignore lint/correctness/useExhaustiveDependencies: keyed on run ids/names, not poll identity
  const caseCommands = useMemo(() => caseOpenCommands(runs ?? []), [runKey]);
  useEffect(() => registerCommands(caseCommands), [caseCommands]);

  const unauthorized =
    runsQuery.isError && runsQuery.error instanceof ApiError && runsQuery.error.status === 401;

  if (unauthorized) {
    return (
      <div className="shell" data-testid="workbench-shell">
        <TokenGate onSaved={() => void queryClient.invalidateQueries({ queryKey: RUNS_QUERY_KEY })} />
        <LiveRegion />
      </div>
    );
  }

  return (
    <>
      <Layout />
      <CaseFeature runId={route.runId} />
      <AnalysisFeature runId={route.runId} />
      <LiveRegion />
    </>
  );
}
