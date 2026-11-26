import { act, cleanup, configure, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_SEARCH_OPTIONS } from "../../api/keywordPacks";
import { resetAppStore, useAppStore } from "../../state/store";
import { useSearchState } from "../case/searchState";
import { installFetch, jsonResponse, renderWithClient } from "../grid/testSupport";
import { useSearchActivity } from "./activity";
import { SearchWorkspace } from "./SearchWorkspace";

// Async waits must not depend on machine speed (CI under load).
configure({ asyncUtilTimeout: 5000 });

const COUNTS: Record<string, number> = {
  급여대장: 283,
  비자금: 7,
  "(급여대장) AND (비자금)": 3,
  "(급여대장) AND NOT (비자금)": 280,
  "(비자금) AND NOT (급여대장)": 4,
};

/** The run's index as the fake server reports it; a test may change it while mounted. */
interface FakeIndex {
  state: "ready" | "none" | "building";
  /** Documents of the index a running build replaces (it keeps answering meanwhile). */
  docCount?: number;
  /** Counts that differ from COUNTS (a rebuilt index). */
  counts?: Record<string, number>;
}

function mount(q: string, index: FakeIndex = { state: "ready" }) {
  resetAppStore({ route: { runId: "r1", collection: "search", q } });
  const calls = installFetch({
    "/search/index/build": () =>
      jsonResponse({ analysis_id: "a1", kind: "search-index", status: "queued", progress: {} }, 202),
    "/search/index": () =>
      jsonResponse(
        index.state === "building"
          ? {
              status: "building",
              doc_count: index.docCount ?? 0,
              building: {
                analysis_id: "a1",
                kind: "search-index",
                status: "running",
                progress: {
                  done: 5,
                  total: 9,
                  unit: "출력 파일",
                  message: "이벤트 로그를 색인했습니다",
                  percent: 55.6,
                },
              },
            }
          : { status: index.state, doc_count: 1030611, building: null },
      ),
    "/search/count": (_url, init) => {
      // Like the server: no index, no counts.
      if (index.state !== "ready" && !index.docCount)
        return jsonResponse({ detail: "검색 색인이 없습니다" }, 404);
      const body: { terms: Array<{ q: string }> } = JSON.parse(String(init?.body));
      const text = body.terms[0]?.q ?? "";
      const count = index.counts?.[text] ?? COUNTS[text] ?? 0;
      return jsonResponse({
        items: [{ q: text, count, count_exact: true, by_domain: count ? { eventlog: count } : {} }],
      });
    },
  });
  const view = renderWithClient(
    <SearchWorkspace runId="r1">
      <p>grid</p>
    </SearchWorkspace>,
  );
  return { calls, ...view };
}

const routedQuery = () => useAppStore.getState().route.q;
const chip = (name: string, pressed: boolean) => screen.findByRole("button", { name, pressed });
const keep = (...searches: string[]) => useSearchState.setState({ recent: { r1: searches } });

beforeEach(() => {
  window.localStorage.clear();
  window.history.replaceState(null, "", "/v2/");
  useSearchState.setState({ keywords: [], options: DEFAULT_SEARCH_OPTIONS, popoverOpen: false, recent: {} });
  useSearchActivity.setState({ pending: null, arrived: null, scanReason: null, cancelled: false });
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("SearchWorkspace chips", () => {
  it("keeps every search of the routed text as a chip with its own count", async () => {
    mount("급여대장 비자금");
    expect(await chip("급여대장 283건", true)).toBeTruthy();
    expect(await chip("비자금 7건", true)).toBeTruthy();
    expect(useSearchState.getState().recent.r1).toEqual(["급여대장", "비자금"]);
  });

  it("a chip shows its search alone; 함께 보기 adds searches and 모두 일치 keeps the rows all of them match", async () => {
    keep("급여대장", "비자금");
    mount("급여대장");
    fireEvent.click(await chip("비자금 7건", false));
    expect(routedQuery()).toBe("비자금");

    fireEvent.click(screen.getByRole("button", { name: "함께 보기" }));
    fireEvent.click(await chip("급여대장 283건", false));
    expect(routedQuery()).toBe("(급여대장) OR (비자금)");
    fireEvent.click(screen.getByRole("button", { name: "모두 일치" }));
    expect(routedQuery()).toBe("(급여대장) AND (비자금)");

    // Leaving 함께 보기 goes back to one search.
    fireEvent.click(screen.getByRole("button", { name: "함께 보기", pressed: true }));
    expect(routedQuery()).toBe("급여대장");
  });

  it("closing the shown chip moves to the search that is left; one search cannot be compared", async () => {
    keep("급여대장", "비자금");
    mount("급여대장");
    fireEvent.click(screen.getByRole("button", { name: "급여대장 검색 닫기" }));
    expect(routedQuery()).toBe("비자금");
    expect(await chip("비자금 7건", true)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "급여대장 검색 닫기" })).toBeNull();
    expect(screen.getByRole("button", { name: "검색 비교" }).getAttribute("aria-disabled")).toBe("true");
  });
});

describe("SearchWorkspace compare table", () => {
  it("counts what two searches share and what only one has, and opens those rows", async () => {
    mount("급여대장 비자금");
    fireEvent.click(screen.getByRole("button", { name: "검색 비교" }));
    expect(await screen.findByRole("button", { name: "급여대장에만 있는 행 280건 보기" })).toBeTruthy();
    expect(await screen.findByRole("button", { name: "비자금에만 있는 행 4건 보기" })).toBeTruthy();
    fireEvent.click(await screen.findByRole("button", { name: "급여대장 그리고 비자금 3건 보기" }));
    expect(routedQuery()).toBe("(급여대장) AND (비자금)");
  });
});

describe("SearchWorkspace status", () => {
  it("says the scan is partial when the run has no index and builds one on request", async () => {
    const { calls } = mount("급여대장", { state: "none" });
    expect(await screen.findByTestId("search-index-notice")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "색인 만들기" }));
    await waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && c.url.endsWith("/search/index/build"))).toBe(true),
    );
    // No index: the chip has no count, and none is asked for.
    expect(await chip("급여대장", true)).toBeTruthy();
    expect(calls.some((c) => c.url.endsWith("/search/count"))).toBe(false);
  });

  it("shows a rebuild's progress and counts again on the new index once it is ready", async () => {
    // The index being replaced still answers while the build runs.
    const index: FakeIndex = { state: "building", docCount: 1000 };
    const { client } = mount("급여대장", index);
    await screen.findByTestId("search-index-building");
    const bar = screen.getByRole("progressbar");
    expect([bar.getAttribute("value"), bar.getAttribute("max")]).toEqual(["5", "9"]);
    expect(await chip("급여대장 283건", true)).toBeTruthy();

    index.state = "ready";
    index.counts = { 급여대장: 290 };
    await act(() => client.invalidateQueries({ queryKey: ["search-index", "r1"] }));
    expect(await chip("급여대장 290건", true)).toBeTruthy();
    expect(screen.queryByTestId("search-index-building")).toBeNull();
  });

  it("cancels a running search: the request is aborted and the line offers to search again", async () => {
    const { client } = mount("급여대장");
    const page = client.fetchQuery({
      queryKey: ["collection", "r1", "search", "page", 0],
      queryFn: ({ signal }) =>
        new Promise<never>((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    });
    act(() => useSearchActivity.getState().begin("scan", null));
    fireEvent.click(await screen.findByRole("button", { name: "검색 취소" }));
    await expect(page).rejects.toBeTruthy();
    expect(await screen.findByTestId("search-cancelled")).toBeTruthy();
    expect(screen.getByRole("button", { name: "다시 검색" })).toBeTruthy();
  });
});
