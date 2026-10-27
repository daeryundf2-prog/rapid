import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GridFooter, type GridFooterProps, searchIndexHint } from "../features/grid/GridToolbar";
import { backendLabel, GRID_FILTER_DEBOUNCE_MS } from "../features/grid/gridUtils";
import { installFetch, jsonResponse } from "../features/grid/testSupport";
import { fetchSearchRows, SEARCH_PAGE_SIZE } from "./collections";
import { forgetSearchIndex, indexCoversSearch } from "./search";

afterEach(() => {
  vi.unstubAllGlobals();
  forgetSearchIndex();
});

const spec = { keywords: ["계약"], mode: "exact" as const };

function hits(from: number, count: number) {
  return Array.from({ length: count }, (_, i) => ({
    source: "artifacts",
    kind: "eventlog",
    pointer: `/artifacts/${from + i}`,
    locator: { collection: "artifacts", kind: "eventlog", pointer: `/artifacts/${from + i}` },
  }));
}

/** A v2 index of `total` hits answering cursor pages ("c<offset>" names the page at offset). */
function indexRoutes(total: number, status = "ready") {
  return {
    "/search/index": () => jsonResponse({ status }),
    "/search/query": (_url: URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { page: { limit: number; cursor?: string } };
      const start = body.page.cursor ? Number(body.page.cursor.slice(1)) : 0;
      const count = Math.max(0, Math.min(body.page.limit, total - start));
      const next = start + count < total ? `c${start + count}` : null;
      return jsonResponse({
        matches: hits(start, count),
        page: { next_cursor: next, returned: count },
        truncated: false,
        elapsed_ms: 7,
        backend: "index",
      });
    },
    "/search": () => jsonResponse({ matches: [], pagination: { has_more: false, total: 0 }, backend: "fts" }),
  };
}

describe("console search over the v2 index (R7 P2)", () => {
  it("uses POST /search/query with keywords when the index is ready, v1 paging semantics", async () => {
    const calls = installFetch(indexRoutes(300));
    const page = await fetchSearchRows("run-a", { search: spec }, SEARCH_PAGE_SIZE);
    const query = calls.filter((call) => call.url.includes("/search/query"));
    expect(query).toHaveLength(1);
    expect(query[0]?.method).toBe("POST");
    expect(query[0]?.body).toEqual({
      keywords: ["계약"],
      page: { limit: 250, offset: 0 },
      aggregates: false,
      facets: false,
    });
    expect(calls.some((call) => call.url.startsWith("/api/runs/run-a/search?"))).toBe(false);
    expect(page.backend).toBe("index");
    expect(page.rows).toHaveLength(250);
    expect(page.hasMore).toBe(true);
    expect(page.total).toBeNull();
    // Page 2 reuses page 1's cursor: one request, the last page carries the total.
    const second = await fetchSearchRows("run-a", { search: spec, offset: 250 }, SEARCH_PAGE_SIZE);
    const after = calls.filter((call) => call.url.includes("/search/query"));
    expect(after).toHaveLength(2);
    expect(after[1]?.body).toMatchObject({ page: { limit: 250, offset: 250, cursor: "c250" } });
    expect(second.rows).toHaveLength(50);
    expect(second.total).toBe(300);
    expect(second.hasMore).toBe(false);
    // The status is read once per run (cached).
    expect(calls.filter((call) => call.url.endsWith("/search/index"))).toHaveLength(1);
  });

  it("a page whose cursor is unknown walks forward from the nearest known one", async () => {
    const calls = installFetch(indexRoutes(2000));
    const page = await fetchSearchRows("run-b", { search: spec, offset: 1250 }, SEARCH_PAGE_SIZE);
    const bodies = calls
      .filter((call) => call.url.includes("/search/query"))
      .map((call) => (call.body as { page: unknown }).page);
    expect(bodies).toEqual([
      { limit: 1000, offset: 0 },
      { limit: 250, offset: 1000, cursor: "c1000" },
      { limit: 250, offset: 1250, cursor: "c1250" },
    ]);
    expect((page.rows[0] as { pointer: string }).pointer).toBe("/artifacts/1250");
  });

  it("falls back to v1 without an index and says so (footer hint)", async () => {
    const calls = installFetch({
      "/search/index": () => jsonResponse({ status: "none" }),
      "/search": () =>
        jsonResponse({ matches: hits(0, 1), backend: "fts", pagination: { has_more: false, total: 1 } }),
    });
    const page = await fetchSearchRows("run-c", { search: spec }, SEARCH_PAGE_SIZE);
    expect(calls.some((call) => call.url.includes("/search/query"))).toBe(false);
    expect(page.backend).toBe("fts");
    expect(page.meta).toEqual({ searchIndex: "none" });
    expect(page.total).toBe(1);
  });

  it("falls back to v1 when the index answers 404/409 (removed or older format)", async () => {
    const calls = installFetch({
      "/search/index": () => jsonResponse({ status: "ready" }),
      "/search/query": () => jsonResponse({ detail: "검색 색인 형식이 오래되었습니다" }, 409),
      "/search": () =>
        jsonResponse({ matches: [], backend: "fts", pagination: { has_more: false, total: 0 } }),
    });
    const page = await fetchSearchRows("run-d", { search: spec }, SEARCH_PAGE_SIZE);
    expect(page.backend).toBe("fts");
    expect(calls.some((call) => call.url.includes("/search?"))).toBe(true);
  });

  it("options v2 does not cover stay on v1 (no index status request)", async () => {
    expect(indexCoversSearch({ ...spec, mode: "regex" }, [])).toBe(false);
    expect(indexCoversSearch({ ...spec, ocr: true }, [])).toBe(false);
    expect(indexCoversSearch({ ...spec, sources: ["files"] }, [])).toBe(false);
    expect(indexCoversSearch({ ...spec, hideKnownGood: true }, [])).toBe(false);
    expect(indexCoversSearch(spec, [".exe"])).toBe(false);
    expect(indexCoversSearch(spec, undefined)).toBe(true);
    const calls = installFetch(indexRoutes(1));
    const page = await fetchSearchRows("run-e", { search: { ...spec, mode: "fuzzy" } }, SEARCH_PAGE_SIZE);
    expect(calls.some((call) => call.url.includes("/search/index"))).toBe(false);
    expect(page.meta).toBeUndefined();
  });

  it("a cancelled v2 request is the search's error, never a silent v1 fallback", async () => {
    installFetch({
      "/search/index": () => jsonResponse({ status: "ready" }),
      "/search/query": () => Promise.reject(new DOMException("aborted", "AbortError")),
    });
    await expect(fetchSearchRows("run-f", { search: spec }, SEARCH_PAGE_SIZE)).rejects.toThrow("aborted");
  });
});

describe("search footer v2 hint and grid debounce (R7 P2)", () => {
  const base: GridFooterProps = {
    page: 1,
    pageCount: null,
    total: null,
    shown: 1,
    backend: "fts",
    elapsedMs: 5,
    truncated: false,
    filtering: false,
    sorting: false,
    loadedCount: 1,
    canLoadMore: false,
    onLoadMore: () => undefined,
    loading: false,
  };

  it("links to the 처리 card of the index when v1 answered for want of one", () => {
    const hint = searchIndexHint("none");
    expect(hint).toEqual({ text: "v2 색인 없음", linkText: "처리 단계에서 만들기" });
    expect(searchIndexHint("ready")).toBeUndefined();
    expect(searchIndexHint(undefined)).toBeUndefined();
    expect(searchIndexHint("stale")?.linkText).toBe("처리 단계에서 다시 만들기");
    // R7 S2: stale also covers an older index format (a v2 index without the bigram table).
    expect(searchIndexHint("stale")?.text).toBe("v2 색인 재생성 필요(런 출력보다 오래됐거나 이전 형식)");
    render(
      <GridFooter
        {...base}
        indexHint={{ ...(hint as NonNullable<typeof hint>), href: "#/case/r1/process/search-index" }}
      />,
    );
    const line = screen.getByTestId("grid-footer-index-hint");
    expect(line.textContent).toBe("v2 색인 없음 — 처리 단계에서 만들기");
    expect(screen.getByRole("link", { name: "처리 단계에서 만들기" }).getAttribute("href")).toBe(
      "#/case/r1/process/search-index",
    );
  });

  it("names the v2 backend and waits 500 ms before a grid text filter is sent", () => {
    expect(backendLabel("index")).toBe("검색 색인(v2)");
    expect(GRID_FILTER_DEBOUNCE_MS).toBe(500);
  });
});
