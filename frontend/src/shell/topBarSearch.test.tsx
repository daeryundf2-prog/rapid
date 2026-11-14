import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { searchSpec } from "../app/gridBridge";
import { searchCancelKey, useSearchState } from "../features/case/searchState";
import { resetAppStore, useAppStore } from "../state/store";
import { searchQueryKey, TopBar } from "./TopBar";

const RUN = "run-p2";

beforeEach(() => {
  window.history.replaceState(null, "", "/v2/");
  resetAppStore({ route: { runId: RUN, collection: "search", q: "계약" } });
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } })),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

/** A search page request that only ends when its AbortSignal fires. */
function startSearch(client: QueryClient, q: string): { signal: () => AbortSignal | undefined } {
  let seen: AbortSignal | undefined;
  void client
    .fetchQuery({
      queryKey: [...searchQueryKey(RUN), q, "page", 0],
      queryFn: ({ signal }) =>
        new Promise((_resolve, reject) => {
          seen = signal;
          signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        }),
    })
    .catch(() => undefined);
  return { signal: () => seen };
}

function renderTopBar(client: QueryClient) {
  return render(
    <QueryClientProvider client={client}>
      <TopBar />
    </QueryClientProvider>,
  );
}

describe("top bar search: spinner and cancel (R7 P2)", () => {
  it("shows a spinner while the search is in flight and Esc aborts it, keeping the text", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    renderTopBar(client);
    const input = screen.getByLabelText("전체 검색어") as HTMLInputElement;
    expect(document.querySelector(".global-search-spinner")).toBeNull();
    const pending = startSearch(client, "계약");
    await waitFor(() => expect(document.querySelector(".global-search-spinner")).not.toBeNull());
    expect(document.querySelector(".global-search")?.getAttribute("aria-busy")).toBe("true");
    act(() => {
      fireEvent.keyDown(input, { key: "Escape" });
    });
    await waitFor(() => expect(pending.signal()?.aborted).toBe(true));
    await waitFor(() => expect(document.querySelector(".global-search-spinner")).toBeNull());
    expect(input.value).toBe("계약");
    // The grid does not request the cancelled search again (focus refetch) until Enter.
    expect(useSearchState.getState().cancelled).toBe(searchCancelKey(RUN, ["계약"]));
    fireEvent.submit(input);
    expect(useSearchState.getState().cancelled).toBeNull();
  });

  it("33 keywords: the search runs on the first 32 with a Korean note (R7 S2 #4)", () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    renderTopBar(client);
    const input = screen.getByLabelText("전체 검색어");
    const words = Array.from({ length: 33 }, (_, i) => `키워드${i + 1}`);
    fireEvent.change(input, { target: { value: words.join(" ") } });
    fireEvent.submit(input);
    expect(useSearchState.getState().keywords).toEqual(words.slice(0, 32));
    expect(useAppStore.getState().notice?.text).toBe("전체 검색: 검색어 32개까지만 사용합니다");
    // The grid's request uses the same 32 (and carries the note for the results footer).
    const spec = searchSpec(words.join(" "));
    expect(spec?.keywords).toHaveLength(32);
    expect(spec?.keywordNote).toBe("검색어 32개까지만 사용합니다");
  });

  it("a new search aborts the previous one's requests; Enter still submits", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    renderTopBar(client);
    const previous = startSearch(client, "계약");
    await waitFor(() => expect(pending(previous)).toBe(false));
    const input = screen.getByLabelText("전체 검색어");
    fireEvent.change(input, { target: { value: "LiveUpdate" } });
    fireEvent.submit(input);
    await waitFor(() => expect(previous.signal()?.aborted).toBe(true));
    expect(window.location.hash).toBe(`#/case/${RUN}/explore/search?q=LiveUpdate`);
  });

  it("a search query created while another component renders logs no React error (R7 S2 confirmation)", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    function Grid() {
      // The query is built and its fetch started (the cache notified) during this render.
      void client.prefetchQuery({
        queryKey: [...searchQueryKey(RUN), "계약", "page", 1],
        queryFn: () => new Promise(() => undefined),
      });
      useQuery({
        queryKey: [...searchQueryKey(RUN), "계약", "page", 0],
        queryFn: () => new Promise(() => undefined),
      });
      return null;
    }
    const tree = (grid: boolean) => (
      <QueryClientProvider client={client}>
        <TopBar />
        {grid ? <Grid /> : null}
      </QueryClientProvider>
    );
    try {
      // The top bar is subscribed to the cache before the grid mounts (a search opened later).
      const { rerender } = render(tree(false));
      rerender(tree(true));
      await waitFor(() => expect(document.querySelector(".global-search-spinner")).not.toBeNull());
      expect(errors).not.toHaveBeenCalled();
    } finally {
      errors.mockRestore();
    }
  });
});

function pending(handle: { signal: () => AbortSignal | undefined }): boolean {
  return handle.signal()?.aborted ?? true;
}
