import { describe, expect, it } from "vitest";
import type { CollectionQuery } from "../../contracts/collection";
import { combineSearches, onlyQuery, parseSearchInput, type SearchCombine, searchPlan } from "./queryModel";

type SearchSpec = NonNullable<CollectionQuery["search"]>;

describe("parseSearchInput", () => {
  const cases: ReadonlyArray<readonly [text: string, searches: string[], combine: SearchCombine]> = [
    ["급여대장", ["급여대장"], "any"],
    // Plain words and commas: one search each, as the scan search always read them.
    ["급여대장 비자금, SanDisk", ["급여대장", "비자금", "SanDisk"], "any"],
    ["a a b", ["a", "b"], "any"],
    // A quoted phrase keeps its spaces; a URL or a drive path is a plain word.
    ['"급여 대장" 비자금', ['"급여 대장"', "비자금"], "any"],
    ["https://a.example/x c:\\users\\a", ["https://a.example/x", "c:\\users\\a"], "any"],
    // A text that uses the grammar is one search, read by the server as written.
    ["AnyDesk in:eventlog", ["AnyDesk in:eventlog"], "any"],
    ["eventid:4624 data.LogonType:10", ["eventid:4624 data.LogonType:10"], "any"],
    [
      "in:(eventlog, registry) time:[2025-05-28 .. 2025-05-30]",
      ["in:(eventlog, registry) time:[2025-05-28 .. 2025-05-30]"],
      "any",
    ],
    ["re:/급여 대장/ x", ["re:/급여 대장/ x"], "any"],
    ["eventid:4624 AND data.LogonType:10", ["eventid:4624 AND data.LogonType:10"], "any"],
    ["AnyDesk -svchost", ["AnyDesk -svchost"], "any"],
    ["(a OR b) AND c", ["(a OR b) AND c"], "any"],
    ["(a) OR (b) AND (c)", ["(a) OR (b) AND (c)"], "any"],
    // The form the chips write.
    ["(급여대장) OR (비자금)", ["급여대장", "비자금"], "any"],
    ["(급여대장) AND (비자금) AND (SanDisk)", ["급여대장", "비자금", "SanDisk"], "all"],
    ["(a b)", ["a b"], "any"],
    ["   ", [], "any"],
  ];
  it.each(cases)("%s", (text, searches, combine) => {
    expect(parseSearchInput(text)).toEqual({ searches, combine });
  });
});

describe("combineSearches", () => {
  const selections: ReadonlyArray<readonly [searches: string[], combine: SearchCombine]> = [
    [["급여대장"], "any"],
    [["급여대장", "비자금"], "any"],
    [["급여대장", "비자금", "SanDisk"], "all"],
    [["a b"], "any"],
    [["eventid:4624 AND data.LogonType:10", "AnyDesk"], "all"],
    [['"급여 대장"', "in:(eventlog, registry)"], "any"],
    [["AnyDesk in:eventlog"], "any"],
    [["(a) AND NOT (b)"], "any"],
  ];
  it.each(selections)("%j (%s) reads back from its query text as the same selection", (searches, combine) => {
    expect(parseSearchInput(combineSearches(searches, combine))).toEqual({ searches, combine });
  });

  it("writes one search as typed and several as a group per search", () => {
    expect(combineSearches(["급여대장"], "all")).toBe("급여대장");
    expect(combineSearches(["급여대장", "비자금"], "any")).toBe("(급여대장) OR (비자금)");
    expect(combineSearches(["급여대장", "비자금"], "all")).toBe("(급여대장) AND (비자금)");
    expect(combineSearches([], "any")).toBe("");
  });
});

describe("onlyQuery", () => {
  it("excludes every other search", () => {
    expect(onlyQuery("a", ["b", "c"])).toBe("(a) AND NOT ((b) OR (c))");
    expect(onlyQuery("a", ["b"])).toBe("(a) AND NOT (b)");
    expect(onlyQuery("a", [])).toBe("a");
  });
});

describe("searchPlan", () => {
  const spec = (over: Partial<SearchSpec> = {}): SearchSpec => ({
    keywords: ["급여대장", "비자금"],
    combine: "any",
    mode: "exact",
    ...over,
  });

  it("runs on the index with the default options", () => {
    expect(searchPlan(spec())).toEqual({ kind: "index", q: "(급여대장) OR (비자금)" });
    expect(searchPlan(spec({ combine: "all" }))).toEqual({ kind: "index", q: "(급여대장) AND (비자금)" });
    expect(searchPlan(spec({ keywords: ["급여대장"], combine: undefined }))).toEqual({
      kind: "index",
      q: "급여대장",
    });
  });

  it("scopes the index query to the chosen sources and extensions", () => {
    expect(
      searchPlan(spec({ keywords: ["급여대장"], sources: ["documents", "files"] }), [".pdf", "hwp"]),
    ).toEqual({
      kind: "index",
      q: "(급여대장) AND in:(docs, files) AND ext:(pdf, hwp)",
    });
  });

  const scanOnly: ReadonlyArray<readonly [name: string, over: Partial<SearchSpec>]> = [
    ["fuzzy matching", { mode: "fuzzy" }],
    ["regex mode", { mode: "regex" }],
    ["hiding known-good files", { hideKnownGood: true }],
    ["the timeline source", { sources: ["files", "timeline"] }],
  ];
  it.each(scanOnly)("leaves %s to the scan", (_name, over) => {
    expect(searchPlan(spec(over)).kind).toBe("scan");
  });
});
