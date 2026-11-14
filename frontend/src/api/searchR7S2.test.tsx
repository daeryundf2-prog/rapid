import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  KEYWORD_COUNT_NOTE,
  KEYWORD_LENGTH_NOTE,
  parseSearchKeywords,
} from "../features/case/searchKeywords";
import { GridFooter } from "../features/grid/GridToolbar";
import { SEARCH_SHORT_KEYWORD_NOTE, searchWarningNote } from "../features/grid/searchNotes";
import { installFetch, jsonResponse } from "../features/grid/testSupport";
import { ApiError } from "./client";
import { fetchSearchRows, SEARCH_PAGE_SIZE } from "./collections";
import {
  forgetSearchIndex,
  indexCoversSearch,
  isUnindexedKeyword,
  koreanSearchError,
  SEARCH_REQUEST_REJECTED,
  searchWarningsOf,
} from "./search";

afterEach(() => {
  cleanup();
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

describe("R7 S2 #3: v2 warnings in the search results footer", () => {
  it("reads string and structured warnings; the footer shows one Korean line with per-source counts", async () => {
    installFetch({
      "/search/index": () => jsonResponse({ status: "ready" }),
      "/search/query": () =>
        jsonResponse({
          matches: [{ source: "documents", pointer: "/candidates/1" }],
          page: { next_cursor: null },
          truncated: false,
          elapsed_ms: 3,
          // Current server: Korean sentences under query.parsed.warnings.
          query: {
            parsed: {
              warnings: [
                "1자 검색어는 색인을 쓰지 못해 전체 본문을 훑습니다(느릴 수 있음)",
                "색인 상한에서 본문 일부가 잘린 행이 있어 그 부분은 검색되지 않습니다(media 1,200건, filesystem 3건)",
              ],
            },
          },
          // Backend lane (R7 S2 fix): structured per-source truncated-row counts.
          warnings: [
            { code: "truncated_rows", message: "본문이 잘린 행", counts: { docs: 7, artifacts: 0 } },
          ],
        }),
    });
    const page = await fetchSearchRows(
      "run-w",
      { search: { keywords: ["계약", "계"], mode: "exact" } },
      SEARCH_PAGE_SIZE,
    );
    const warnings = page.meta?.searchWarnings as { kind: string; counts?: Record<string, number> }[];
    expect(warnings.map((w) => w.kind)).toEqual(["truncated-rows", "short-keyword", "truncated-rows"]);
    expect(warnings[0]?.counts).toEqual({ docs: 7 });
    expect(warnings[2]?.counts).toEqual({ media: 1200, filesystem: 3 });

    const note = searchWarningNote(page.meta?.searchWarnings);
    expect(note?.text).toBe(
      `검색 참고: 본문이 색인 상한에서 잘린 행 1,210건은 뒷부분이 검색되지 않았습니다 · ${SEARCH_SHORT_KEYWORD_NOTE}`,
    );
    expect(note?.text).not.toMatch(/[A-Za-z]/);
    expect(note?.title.split("\n").slice(0, 4)).toEqual([
      "출처별 잘린 행:",
      "· 문서·미디어 1,200건",
      "· 문서 7건",
      "· 파일 시스템 3건",
    ]);

    render(
      <GridFooter
        page={1}
        pageCount={null}
        total={1}
        shown={1}
        backend="index"
        elapsedMs={3}
        truncated={false}
        filtering={false}
        sorting={false}
        loadedCount={1}
        canLoadMore={false}
        onLoadMore={() => {}}
        loading={false}
        searchNote={note}
      />,
    );
    const line = screen.getByTestId("grid-footer-search-note");
    expect(line.textContent).toBe(note?.text);
    expect(line.getAttribute("title")).toContain("· 문서·미디어 1,200건");
  });

  it("no warnings, no note (and v1 pages carry none)", () => {
    expect(searchWarningNote(undefined)).toBeUndefined();
    expect(searchWarningNote([])).toBeUndefined();
  });

  it("reads the backend lane's sentence (Korean source labels after '본문이 잘린 행:')", () => {
    const warnings = searchWarningsOf({
      query: {
        parsed: {
          warnings: [
            "색인 상한에서 본문 일부가 잘린 행이 있어 잘린 뒷부분은 검색되지 않습니다(본문이 잘린 행: 아티팩트 1,045건, 문서 8건)",
          ],
        },
      },
    });
    expect(warnings).toEqual([
      expect.objectContaining({ kind: "truncated-rows", counts: { 아티팩트: 1045, 문서: 8 } }),
    ]);
    const note = searchWarningNote(warnings);
    expect(note?.text).toBe("검색 참고: 본문이 색인 상한에서 잘린 행 1,053건은 뒷부분이 검색되지 않았습니다");
    expect(note?.title).toContain("· 아티팩트 1,045건");
  });
});

describe("R7 S2 #4: keyword caps, v1 fallback on 400/422, Korean errors only", () => {
  it("caps keywords at 32 and their total length at 4,000 characters", () => {
    const many = Array.from({ length: 40 }, (_, i) => `k${i}`);
    expect(parseSearchKeywords(many.join(","))).toEqual({
      keywords: many.slice(0, 32),
      note: KEYWORD_COUNT_NOTE,
    });
    const long = ["a".repeat(3000), "b".repeat(1500), "c"];
    expect(parseSearchKeywords(long.join(" "))).toEqual({ keywords: [long[0]], note: KEYWORD_LENGTH_NOTE });
    expect(parseSearchKeywords("x".repeat(5000)).keywords[0]).toHaveLength(4000);
    expect(parseSearchKeywords("계약 계약 근로")).toEqual({ keywords: ["계약", "근로"] });
  });

  it("a v2 422 / 400 falls back to v1 without forgetting the index", async () => {
    for (const status of [422, 400]) {
      const calls = installFetch({
        "/search/index": () => jsonResponse({ status: "ready" }),
        "/search/query": () =>
          jsonResponse(
            status === 422
              ? { detail: [{ msg: "List should have at most 32 items after validation, not 33" }] }
              : { detail: "질의가 너무 깁니다(최대 4,000자)" },
            status,
          ),
        "/search": () =>
          jsonResponse({
            matches: [{ source: "files" }],
            backend: "fts",
            pagination: { has_more: false, total: 1 },
          }),
      });
      const page = await fetchSearchRows(
        `run-4-${status}`,
        { search: { keywords: ["계약서", "근로계약"], mode: "exact" } },
        SEARCH_PAGE_SIZE,
      );
      expect(page.backend).toBe("fts");
      expect(page.rows).toHaveLength(1);
      // Not "no index": the footer offers no index build for a rejected request.
      expect(page.meta).toBeUndefined();
      expect(calls.some((call) => call.url.includes("/search?"))).toBe(true);
      vi.unstubAllGlobals();
    }
  });

  it("English validation text from v1 becomes Korean; Korean reasons pass unchanged", async () => {
    installFetch({
      "/search": () =>
        jsonResponse(
          { detail: [{ msg: "Input should be less than or equal to 1000", loc: ["query", "limit"] }] },
          422,
        ),
    });
    const error = await fetchSearchRows(
      "run-4e",
      { search: { keywords: ["계약"], mode: "regex" } },
      250,
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).message).toBe(SEARCH_REQUEST_REJECTED);
    expect((error as ApiError).message).not.toMatch(/[A-Za-z]/);
    const korean = new ApiError("검색 예산이 끝나 이어서 볼 수 없습니다", 400, null);
    expect(koreanSearchError(korean)).toBe(korean);
  });
});

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

    const long = await fetchSearchRows(
      "run-s",
      { search: { ...base, keywords: ["계약"] } },
      SEARCH_PAGE_SIZE,
    );
    expect(long.backend).toBe("index");
    expect(calls.some((call) => call.url.includes("/search/query"))).toBe(true);
  });
});
