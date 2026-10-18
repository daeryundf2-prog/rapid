// A run that stops (active → idle) stops polling its tree data: the tree refetches the final
// run tree, summary, dashboard and review counts once instead of keeping a mid-run snapshot.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RUNS_QUERY_KEY, type RunWithProgress } from "../../api/runsProgress";
import { installFetch } from "../grid/testSupport";
import { RUN_FINISH_QUERY_KEYS, useTreeData } from "./useTreeModel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("tree data when the run finishes", () => {
  it("invalidates run-tree, run-summary, run-dashboard and review-counts once on active → idle", async () => {
    installFetch({});
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
    const setRuns = (status: string) =>
      client.setQueryData<RunWithProgress[]>(RUNS_QUERY_KEY, [{ run_id: "r1", status }]);
    setRuns("running");
    const invalidate = vi.spyOn(client, "invalidateQueries");
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
    const { result } = renderHook(() => useTreeData("r1"), { wrapper });
    expect(result.current.live.active).toBe(true);
    const finishCalls = () =>
      invalidate.mock.calls.filter(([filters]) =>
        (RUN_FINISH_QUERY_KEYS as readonly string[]).includes(String(filters?.queryKey?.[0])),
      );
    expect(finishCalls()).toHaveLength(0);

    await act(async () => {
      setRuns("completed");
    });
    await waitFor(() => expect(result.current.live.active).toBe(false));
    expect(finishCalls().map(([filters]) => filters?.queryKey)).toEqual(
      RUN_FINISH_QUERY_KEYS.map((key) => [key, "r1"]),
    );

    // Still idle on the next render: no second round.
    await act(async () => {
      setRuns("completed");
    });
    expect(finishCalls()).toHaveLength(RUN_FINISH_QUERY_KEYS.length);
  });
});
