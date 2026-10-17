import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo } from "react";
import { LiveRegion } from "../a11y";
import { ApiError } from "../api/client";
import { RUNS_QUERY_KEY, useRunsPoll } from "../api/runsProgress";
import { caseOpenCommands, registerBuiltinCommands } from "../commands/builtin";
import { registerCommands } from "../commands/registry";
import { AnalysisFeature } from "../features/analysis/AnalysisFeature";
import { CaseFeature } from "../features/case/CaseFeature";
import { DerivedFeature } from "../features/derived/DerivedFeature";
import { useFamilyCatalogLoader } from "../features/flags/catalog";
import { useReviewInvalidation } from "../features/grid/reviewMap";
import { registerStageCommands } from "../features/stages/stages";
import { installPopoutHost, popoutCommands } from "../features/viewer/popout/host";
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
  // Family catalogue (U-F3/U-F4): the bundled fallback until the server's loads.
  useFamilyCatalogLoader(!runsQuery.isError);
  useReviewInvalidation();

  useEffect(() => registerBuiltinCommands(queryClient), [queryClient]);
  useEffect(() => registerStageCommands(), []);
  // 뷰어 창 모드 (U-F2): Ctrl+Shift+V, 되돌리기, and the popout's requests.
  useEffect(() => registerCommands(popoutCommands()), []);
  useEffect(() => installPopoutHost(queryClient), [queryClient]);

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
      <DerivedFeature runId={route.runId} />
      <LiveRegion />
    </>
  );
}
