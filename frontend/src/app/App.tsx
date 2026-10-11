import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo } from "react";
import { LiveRegion } from "../a11y";
import { ApiError } from "../api/client";
import { RUNS_QUERY_KEY, useRunsPoll } from "../api/runsProgress";
import { caseOpenCommands, registerBuiltinCommands } from "../commands/builtin";
import { registerCommands } from "../commands/registry";
import { CaseFeature } from "../features/case/CaseFeature";
import { useReviewInvalidation } from "../features/grid/reviewMap";
import { Layout } from "../shell/Layout";
import { useShortcuts } from "../shortcuts";
import { useRoute } from "../state/hooks";
import { systemTheme } from "../state/slices/prefs";
import { useAppStore } from "../state/store";
import { TokenGate } from "./TokenGate";

function useSystemThemeListener(): void {
  const setSystemTheme = useAppStore((s) => s.setSystemTheme);
  useEffect(() => {
    if (!window.matchMedia) return;
    const list = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => setSystemTheme(systemTheme());
    onChange();
    list.addEventListener?.("change", onChange);
    return () => list.removeEventListener?.("change", onChange);
  }, [setSystemTheme]);
}

/** Shell root: commands, key map, runs poller, token gate, layout. */
export function App() {
  const queryClient = useQueryClient();
  const runsQuery = useRunsPoll();
  const { route } = useRoute();
  useShortcuts();
  useSystemThemeListener();
  useReviewInvalidation();

  useEffect(() => registerBuiltinCommands(queryClient), [queryClient]);

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
      <LiveRegion />
    </>
  );
}
