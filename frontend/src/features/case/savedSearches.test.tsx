import { focusManager, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { invalidateSavedSearches, SAVED_SEARCHES_STALE_MS, useSavedSearches } from "./savedSearches";
import { mockFetch } from "./testUtils";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  focusManager.setFocused(undefined);
});

function Probe({ runId }: { runId: string }) {
  const saved = useSavedSearches(runId, "/o/case.db", "run-r1");
  return <div data-testid="names">{(saved.data ?? []).map((item) => item.name).join(",")}</div>;
}

describe("useSavedSearches (R7 S2)", () => {
  it("does not refetch on window focus, and refetches after an explicit invalidate", async () => {
    let names = ["계좌"];
    const { calls } = mockFetch({
      "POST /api/case-db/saved-searches/list": () => ({ saved_searches: names.map((name) => ({ name })) }),
    });
    // Default staleTime 0 (the app's is 2 s): without the hook's options every focus would refetch.
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 } } });
    const listCalls = () => calls.filter((call) => call.url === "/api/case-db/saved-searches/list").length;
    render(
      <QueryClientProvider client={client}>
        <Probe runId="r1" />
        <Probe runId="r1" />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getAllByTestId("names")[0]?.textContent).toBe("계좌"));
    expect(listCalls()).toBe(1); // dashboard + tree share one request

    const query = client.getQueryCache().find({ queryKey: ["saved-searches", "r1", "/o/case.db"] });
    expect(query?.options).toMatchObject({ staleTime: SAVED_SEARCHES_STALE_MS, refetchOnWindowFocus: false });
    expect(SAVED_SEARCHES_STALE_MS).toBeGreaterThanOrEqual(60_000);

    // Focus churn (the QA session's ~200 refetches) no longer reaches the server.
    for (let index = 0; index < 5; index += 1) {
      act(() => {
        focusManager.setFocused(false);
        focusManager.setFocused(true);
      });
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(listCalls()).toBe(1);

    // A save invalidates every list of the run.
    names = ["계좌", "내 검색"];
    await act(() => invalidateSavedSearches(client, "r1"));
    await waitFor(() => expect(screen.getAllByTestId("names")[0]?.textContent).toBe("계좌,내 검색"));
    expect(listCalls()).toBe(2);
  });
});
