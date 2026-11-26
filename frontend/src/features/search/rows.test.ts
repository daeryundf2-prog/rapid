import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CollectionQuery } from "../../contracts/collection";
import { installFetch, jsonResponse } from "../grid/testSupport";
import { useSearchActivity } from "./activity";
import { fetchSearchPage, resetSearchCursors } from "./rows";

const SPEC: NonNullable<CollectionQuery["search"]> = {
  keywords: ["급여대장"],
  combine: "any",
  mode: "exact",
};
const PAGE = 250;

const hit = (n: number) => ({
  doc_id: n,
  collection: "artifacts",
  kind: "eventlog",
  locator: `/artifacts/${n}`,
});

/** Index endpoint serving `total` hits; its cursor is the offset the next page starts at. */
function indexOf(total: number) {
  return (_url: URL, init: RequestInit | undefined) => {
    const body: { page: { limit: number; cursor?: string } } = JSON.parse(String(init?.body));
    const start = body.page.cursor ? Number(body.page.cursor) : 0;
    const rows = Array.from({ length: Math.min(body.page.limit, total - start) }, (_, i) => hit(start + i));
    const end = start + rows.length;
    return jsonResponse({
      rows,
      page: { next_cursor: end < total ? String(end) : null },
      elapsed_ms: 12,
      truncated: false,
      query: { parsed: { warnings: ["2자 이하 검색어는 느립니다"] } },
    });
  };
}

const scanOf = (count: number) => () =>
  jsonResponse({
    backend: "scan",
    truncated: true,
    elapsed_ms: 14_000,
    matches: Array.from({ length: count }, (_, i) => ({ source: "files", pointer: `/candidates/${i}` })),
  });

const noIndex = () => jsonResponse({ detail: "검색 색인이 없습니다. 처리 단계에서 색인을 만드세요" }, 404);

/** Resolves once the activity store reports `backend` as pending (subscribed before the request). */
function pendingBackend(backend: "index" | "scan"): Promise<void> {
  return new Promise((resolve) => {
    const off = useSearchActivity.subscribe((state) => {
      if (state.pending !== backend) return;
      off();
      resolve();
    });
  });
}

beforeEach(() => {
  resetSearchCursors();
  useSearchActivity.setState({ pending: null, arrived: null, scanReason: null, cancelled: false });
});
afterEach(() => vi.unstubAllGlobals());

describe("fetchSearchPage on the index", () => {
  it("asks for rows only, then pages by the cursor of the page before", async () => {
    const calls = installFetch({ "/search/query": indexOf(300) });
    const first = await fetchSearchPage("r1", { search: SPEC, offset: 0, limit: PAGE });
    expect(calls[0]).toMatchObject({
      url: "/api/runs/r1/search/query",
      method: "POST",
      body: { q: "급여대장", aggregates: false, page: { limit: PAGE } },
    });
    // More rows exist and the total is not known yet: the count is its own request.
    expect(first).toMatchObject({ total: null, hasMore: true, backend: "index", elapsedMs: 12 });
    expect(first.rows).toHaveLength(PAGE);

    const second = await fetchSearchPage("r1", { search: SPEC, offset: PAGE, limit: PAGE });
    expect(calls[1]?.body).toMatchObject({ page: { limit: PAGE, cursor: "250" } });
    expect(second.rows.map((row) => row.doc_id)).toEqual(Array.from({ length: 50 }, (_, i) => 250 + i));
    // The last page fixes the total.
    expect(second).toMatchObject({ total: 300, hasMore: false, offset: PAGE });
  });

  it("walks up to a page whose cursor is gone (rebuilt index)", async () => {
    const calls = installFetch({ "/search/query": indexOf(300) });
    await fetchSearchPage("r1", { search: SPEC, offset: 0, limit: PAGE });
    resetSearchCursors();
    const page = await fetchSearchPage("r1", { search: SPEC, offset: PAGE, limit: PAGE });
    expect(page.rows[0]?.doc_id).toBe(250);
    expect(calls.slice(1).map((call) => call.body)).toMatchObject([
      { page: { limit: PAGE } },
      { page: { limit: PAGE, cursor: "250" } },
    ]);
  });

  it("reports the first page as pending on the index, then its warnings", async () => {
    installFetch({ "/search/query": indexOf(3) });
    const request = fetchSearchPage("r1", { search: SPEC, offset: 0, limit: PAGE });
    expect(useSearchActivity.getState().pending).toBe("index");
    await request;
    expect(useSearchActivity.getState()).toMatchObject({
      pending: null,
      arrived: { backend: "index", warnings: ["2자 이하 검색어는 느립니다"] },
    });
  });

  it("gives a query error back to the grid and leaves nothing pending", async () => {
    installFetch({
      "/search/query": () => jsonResponse({ detail: "질의 1번째 글자: 닫는 괄호가 없습니다" }, 400),
    });
    await expect(fetchSearchPage("r1", { search: SPEC, offset: 0, limit: PAGE })).rejects.toThrow(
      "질의 1번째 글자: 닫는 괄호가 없습니다",
    );
    expect(useSearchActivity.getState().pending).toBeNull();
  });
});

describe("fetchSearchPage on the scan", () => {
  it("scans once when the run has no index and cuts the grid pages from that response", async () => {
    const calls = installFetch({ "/search/query": noIndex, "/search": scanOf(300) });
    const scanning = pendingBackend("scan");
    const first = await fetchSearchPage("r1", { search: SPEC, offset: 0, limit: PAGE });
    await scanning;
    expect(first).toMatchObject({ total: 300, backend: "scan", truncated: true, offset: 0 });
    expect(first.rows).toHaveLength(PAGE);
    const second = await fetchSearchPage("r1", { search: SPEC, offset: PAGE, limit: PAGE });
    expect(second.rows.map((row) => row.pointer)).toEqual(
      Array.from({ length: 50 }, (_, i) => `/candidates/${250 + i}`),
    );
    expect(calls.filter((call) => call.url.startsWith("/api/runs/r1/search?"))).toHaveLength(1);
    expect(useSearchActivity.getState()).toMatchObject({ arrived: { backend: "scan" }, scanReason: null });
  });

  it("never asks the index for an option only the scan has, and says why", async () => {
    const calls = installFetch({ "/search/query": indexOf(3), "/search": scanOf(2) });
    const page = await fetchSearchPage("r1", {
      search: { ...SPEC, mode: "fuzzy", sources: ["files"] },
      extension: [".txt"],
      offset: 0,
      limit: PAGE,
    });
    expect(page.rows).toHaveLength(2);
    expect(calls).toHaveLength(1);
    const url = new URL(calls[0]?.url ?? "", "http://x");
    expect(url.pathname).toBe("/api/runs/r1/search");
    expect(url.searchParams.getAll("keyword")).toEqual(["급여대장"]);
    expect(url.searchParams.get("search_mode")).toBe("fuzzy");
    expect(url.searchParams.getAll("source")).toEqual(["files"]);
    expect(url.searchParams.getAll("extension")).toEqual([".txt"]);
    expect(useSearchActivity.getState().scanReason).not.toBeNull();
  });
});
