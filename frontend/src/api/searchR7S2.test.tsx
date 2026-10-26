import { afterEach, describe, expect, it, vi } from "vitest";
import { installFetch, jsonResponse } from "../features/grid/testSupport";
import { fetchSearchRows, SEARCH_PAGE_SIZE } from "./collections";
import { forgetSearchIndex, indexCoversSearch, isUnindexedKeyword } from "./search";

afterEach(() => {
  vi.unstubAllGlobals();
  forgetSearchIndex();
});

function readyIndex() {
  return {
    "/search/index": () => jsonResponse({ status: "ready" }),
    "/search/query": () =>
      jsonResponse({ matches: [], page: { next_cursor: null }, truncated: false, elapsed_ms: 1 }),
    "/search": () => jsonResponse({ matches: [], backend: "fts", pagination: { has_more: false, total: 0 } }),
  };
}

describe("R7 S2 #9: keywords the v2 index cannot look up go to v1", () => {
  it("classifies 1-char and ASCII-containing 2-char keywords as unindexed", () => {
    expect(isUnindexedKeyword("계")).toBe(true);
    expect(isUnindexedKeyword("a")).toBe(true);
    expect(isUnindexedKeyword("ab")).toBe(true);
    expect(isUnindexedKeyword("a계")).toBe(true);
    expect(isUnindexedKeyword("12")).toBe(true);
    expect(isUnindexedKeyword("계약")).toBe(false);
    expect(isUnindexedKeyword("abc")).toBe(false);
    // Code points, not UTF-16 units: one astral character is one character.
    expect(isUnindexedKeyword("𠀀")).toBe(true);
  });

  it("routes all-short searches to v1 and any indexable keyword to v2", async () => {
    const base = { mode: "exact" as const };
    expect(indexCoversSearch({ ...base, keywords: ["계"] }, [])).toBe(false);
    expect(indexCoversSearch({ ...base, keywords: ["ab", "x", "계"] }, [])).toBe(false);
    expect(indexCoversSearch({ ...base, keywords: ["ab", "계약"] }, [])).toBe(true);
    expect(indexCoversSearch({ ...base, keywords: ["LiveUpdate"] }, [])).toBe(true);

    const calls = installFetch(readyIndex());
    const short = await fetchSearchRows("run-s", { search: { ...base, keywords: ["ab"] } }, SEARCH_PAGE_SIZE);
    expect(short.backend).toBe("fts");
    expect(calls.some((call) => call.url.includes("/search/index"))).toBe(false);
    expect(calls.some((call) => call.url.includes("/search/query"))).toBe(false);

    const long = await fetchSearchRows("run-s", { search: { ...base, keywords: ["계약"] } }, SEARCH_PAGE_SIZE);
    expect(long.backend).toBe("index");
    expect(calls.some((call) => call.url.includes("/search/query"))).toBe(true);
  });
});
