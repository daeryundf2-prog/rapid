import { afterEach, describe, expect, it, vi } from "vitest";
import { mockFetch } from "../features/case/testUtils";
import { fetchSearchRows, fieldSearchRefusal } from "./collections";
import {
  FIELD_SEARCH_INDEX_BUILDING,
  FIELD_SEARCH_NEEDS_INDEX,
  FIELD_SEARCH_OPTIONS,
  FIELD_SEARCH_STALE_INDEX,
  forgetSearchIndex,
} from "./search";

/** E01 QA D3: a stale index still answers field keywords; stale and missing read differently. */
describe("field keyword search over a stale index", () => {
  afterEach(() => {
    forgetSearchIndex();
    vi.unstubAllGlobals();
  });

  it("queries the existing stale index and marks the page stale (rebuild hint)", async () => {
    const { calls } = mockFetch({
      "GET /api/runs/r1/search/index": {
        status: "stale",
        stale_reason: "색인에 없는 분석 결과가 있습니다(1개)",
      },
      "POST /api/runs/r1/search/query": {
        matches: [{ path: "a.txt", source: "docs" }],
        page: { next_cursor: null },
        warnings: ["색인이 런 출력보다 오래되었습니다. 결과가 최신이 아닐 수 있습니다"],
      },
    });
    const page = await fetchSearchRows("r1", { search: { keywords: ["lang:ko"], mode: "exact" } }, 50);
    expect(calls.some((call) => call.method === "POST" && call.url.endsWith("/search/query"))).toBe(true);
    expect(page.rows).toHaveLength(1);
    expect(page.backend).toBe("index");
    expect(page.meta?.searchIndex).toBe("stale");
    const warnings = page.meta?.searchWarnings as Array<{ text: string }>;
    expect(warnings.map((w) => w.text).join(" ")).toContain("오래되었습니다");
  });

  it("a plain keyword over a stale index still uses v1 (no field meaning lost)", async () => {
    const { calls } = mockFetch({
      "GET /api/runs/r1/search/index": { status: "stale" },
      "GET /api/runs/r1/search": { matches: [], pagination: { has_more: false, total: 0 } },
    });
    await fetchSearchRows("r1", { search: { keywords: ["invoice"], mode: "exact" } }, 50);
    expect(calls.some((call) => call.url.includes("/search/query"))).toBe(false);
  });

  it("names the missing, stale, building and options cases differently", () => {
    expect(fieldSearchRefusal(true, "none")).toBe(FIELD_SEARCH_NEEDS_INDEX);
    expect(fieldSearchRefusal(true, "stale")).toBe(FIELD_SEARCH_STALE_INDEX);
    expect(fieldSearchRefusal(true, "building")).toBe(FIELD_SEARCH_INDEX_BUILDING);
    expect(fieldSearchRefusal(false, undefined)).toBe(FIELD_SEARCH_OPTIONS);
    expect(FIELD_SEARCH_STALE_INDEX).toContain("다시 만드세요");
    expect(FIELD_SEARCH_STALE_INDEX).not.toBe(FIELD_SEARCH_NEEDS_INDEX);
    expect(FIELD_SEARCH_NEEDS_INDEX).toContain("색인이 없습니다");
  });
});
