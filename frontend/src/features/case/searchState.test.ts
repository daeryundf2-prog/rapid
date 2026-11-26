import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MAX_RECENT_SEARCHES, useSearchState } from "./searchState";

beforeEach(() => {
  window.localStorage.clear();
  useSearchState.setState({ recent: {} });
});
afterEach(() => window.localStorage.clear());

const remember = (runId: string, searches: string[]) =>
  useSearchState.getState().rememberSearches(runId, searches);
const chips = (runId: string) => useSearchState.getState().recent[runId];

describe("search chips kept per run", () => {
  it("keeps searches in the order they were first run, each once, apart per run", () => {
    remember("r1", ["급여대장", "비자금"]);
    remember("r1", ["비자금", "SanDisk"]);
    remember("r2", ["AnyDesk"]);
    expect(chips("r1")).toEqual(["급여대장", "비자금", "SanDisk"]);
    expect(chips("r2")).toEqual(["AnyDesk"]);
  });

  it("drops the oldest chips outside the newest search once the cap is reached", () => {
    const first = Array.from({ length: MAX_RECENT_SEARCHES }, (_, i) => `검색${i}`);
    remember("r1", first);
    remember("r1", ["검색0", "새 검색"]);
    expect(chips("r1")).toEqual(["검색0", ...first.slice(2), "새 검색"]);
  });

  it("forgets one chip and survives a reload through the stored copy", () => {
    remember("r1", ["급여대장", "비자금"]);
    useSearchState.getState().forgetSearch("r1", "급여대장");
    expect(chips("r1")).toEqual(["비자금"]);
    expect(JSON.parse(window.localStorage.getItem("rapidtriage.search.recent") ?? "{}")).toEqual({
      r1: ["비자금"],
    });
  });
});
