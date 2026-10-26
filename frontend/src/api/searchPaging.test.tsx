import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { searchCollection } from "../features/grid/columns/search";
import {
  GridFooter,
  type GridFooterProps,
  SEARCH_TRUNCATED_NOTICE,
  searchLoadedText,
} from "../features/grid/GridToolbar";
import { installFetch, jsonResponse } from "../features/grid/testSupport";
import { fetchSearchRows, SEARCH_PAGE_SIZE } from "./collections";
import { DEFAULT_SEARCH_OPTIONS } from "./keywordPacks";

afterEach(() => vi.unstubAllGlobals());

const spec = { keywords: ["계약"], mode: "exact" as const };

describe("fetchSearchRows paging (R7)", () => {
  it("asks for one page with the light defaults and reports hasMore / unknown total", async () => {
    const calls = installFetch({
      "/search": () =>
        jsonResponse({
          matches: [{ pointer: "/events/1" }, { pointer: "/events/2" }],
          backend: "fts",
          truncated: false,
          elapsed_ms: 12,
          pagination: { offset: 250, limit: 250, returned: 2, has_more: true, next_offset: 252, total: null },
        }),
    });
    const page = await fetchSearchRows("r1", { search: spec, offset: 250 }, SEARCH_PAGE_SIZE);
    const params = new URL(calls[0]?.url ?? "", "http://x").searchParams;
    expect(params.get("limit")).toBe("250");
    expect(params.get("offset")).toBe("250");
    // analysis / ocr / detail / metadata stay at the server defaults (nothing extra sent).
    for (const key of ["analysis", "ocr", "detail", "metadata"]) expect(params.has(key)).toBe(false);
    expect(page.offset).toBe(250);
    expect(page.hasMore).toBe(true);
    expect(page.total).toBeNull();
    expect(page.rows).toHaveLength(2);
  });

  it("the last page carries the total; OCR is requested only when the options ask", async () => {
    const calls = installFetch({
      "/search": () =>
        jsonResponse({
          matches: [{ pointer: "/events/1" }],
          backend: "fts",
          truncated: false,
          pagination: { offset: 0, limit: 250, returned: 1, has_more: false, next_offset: null, total: 1 },
        }),
    });
    const page = await fetchSearchRows("r1", { search: { ...spec, ocr: true } }, SEARCH_PAGE_SIZE);
    expect(new URL(calls[0]?.url ?? "", "http://x").searchParams.get("ocr")).toBe("1");
    expect(page.total).toBe(1);
    expect(page.hasMore).toBe(false);
  });

  it("a budget-truncated last page has no exact total", async () => {
    installFetch({
      "/search": () =>
        jsonResponse({
          matches: [{ pointer: "/events/1" }],
          backend: "fts",
          truncated: true,
          pagination: { offset: 0, limit: 250, returned: 1, has_more: false, next_offset: null, total: null },
        }),
    });
    const page = await fetchSearchRows("r1", { search: spec }, SEARCH_PAGE_SIZE);
    expect(page.total).toBeNull();
    expect(page.truncated).toBe(true);
  });

  it("the search collection pages on the server; OCR is off by default", () => {
    expect(searchCollection.source).toBe("paged");
    expect(DEFAULT_SEARCH_OPTIONS.ocr).toBe(false);
  });
});

describe("search footer (R7)", () => {
  it("states loaded vs total", () => {
    expect(searchLoadedText(250, 441, true)).toBe("불러온 250건 / 전체 441건");
    expect(searchLoadedText(441, 441, false)).toBe("전체 441건 모두 불러옴");
    expect(searchLoadedText(250, null, true)).toContain("더 있음");
    expect(searchLoadedText(12, null, false)).toBe("불러온 12건");
  });

  it("shows the search truncation note and the loaded line", () => {
    const props: GridFooterProps = {
      page: 1,
      pageCount: null,
      total: null,
      shown: 250,
      backend: "fts",
      elapsedMs: 900,
      truncated: true,
      filtering: false,
      sorting: false,
      loadedCount: 250,
      canLoadMore: false,
      onLoadMore: () => {},
      loading: false,
      truncatedText: SEARCH_TRUNCATED_NOTICE,
      loadedSummary: searchLoadedText(250, null, true),
    };
    render(<GridFooter {...props} />);
    expect(screen.getByRole("note").textContent).toBe(SEARCH_TRUNCATED_NOTICE);
    expect(screen.getByTestId("grid-footer-loaded").textContent).toContain("불러온 250건");
  });
});
