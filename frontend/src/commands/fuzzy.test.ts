import { describe, expect, it } from "vitest";
import { fuzzyMatchIndexes, fuzzyScore } from "./fuzzy";

describe("fuzzyMatchIndexes (palette highlight, review #12)", () => {
  it("marks a substring hit as one run, else the in-order characters fuzzyScore matched", () => {
    expect(fuzzyMatchIndexes("리뷰", "이동: 리뷰보드")).toEqual([4, 5]);
    expect(fuzzyMatchIndexes("tmln", "timeline")).toEqual([0, 2, 4, 6]);
    expect(fuzzyMatchIndexes("TIME", "timeline")).toEqual([0, 1, 2, 3]);
    expect(fuzzyMatchIndexes("r v", "review")).toEqual([0, 2]);
  });

  it("is empty for an empty query or when only the command id matched", () => {
    expect(fuzzyMatchIndexes("", "아무거나")).toEqual([]);
    expect(fuzzyMatchIndexes("navigate", "이동: 타임라인")).toEqual([]);
    expect(fuzzyScore("navigate", "이동: 타임라인 navigate.timeline")).not.toBeNull();
  });
});
