/**
 * T-175 (r8 design system "시각 열 176px 고정", IS-020 / QA-044): the artifacts 시각 column and the
 * kind time columns are 176px wide, neither grow nor shrink below that, and their cell text is
 * "YYYY-MM-DD HH:MM:SS" (the zone is in the tooltip), so the cell never truncates.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GridRow } from "../../../contracts/collection";
import { useAppStore } from "../../../state/store";
import { analysisCollection } from "./analysis";
import { artifactsCollection, kindColumn } from "./artifacts";
import { fitMinWidth, growWeight, makeRef, makeRow } from "./common";
import { catalogColumn, mixedSummaryColumns, TIME_CHIP_COLUMN_WIDTH } from "./families";
import { filesCollection } from "./files";
import { reviewCollection } from "./review";
import { searchCollection } from "./search";
import { gridTimeText, TIME_COLUMN_WIDTH } from "./TimelineCells";
import { timelineCollection } from "./timeline";

const ISO = "2026-03-01T00:12:33Z";
const WALL = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
// Cell padding (2 × --space-2) + 19 characters at a generous 13px-table glyph width.
const CELL_PADDING = 16;
const MAX_GLYPH = 7.6;

beforeEach(() => useAppStore.setState({ timezone: "utc" }));
afterEach(() => useAppStore.setState({ timezone: null }));

function row(details: Record<string, unknown>): GridRow {
  return makeRow(
    makeRef("artifacts", "/artifacts/0", "browser"),
    { title: "x", timestamp: ISO },
    { details },
  );
}

describe("시각 열 고정 폭 (T-175)", () => {
  it("is 176px, never grows and never shrinks below 176 (viewer open: other columns hide)", () => {
    const time = artifactsCollection.columns.find((c) => c.id === "timestamp");
    expect(time?.width).toBe(TIME_COLUMN_WIDTH);
    expect(time?.minWidth).toBe(176);
    expect(time && fitMinWidth(time)).toBe(176);
    expect(time && growWeight(time)).toBe(0);
  });

  it("shows the wall-clock time without the zone; the tooltip keeps the full reading", () => {
    const time = artifactsCollection.columns.find((c) => c.id === "timestamp");
    const text = time?.format?.(row({})) ?? "";
    expect(text).toBe("2026-03-01 00:12:33");
    expect(text).toMatch(WALL);
    expect(text.length * MAX_GLYPH + CELL_PADDING).toBeLessThanOrEqual(TIME_COLUMN_WIDTH);
    expect(time?.tooltip?.(row({}))).toContain("UTC");
  });

  it("kind time columns are 176px fixed with the same text and a zone tooltip", () => {
    const spec = kindColumn({ header: "방문 시각", keys: ["visited_at"], time: true, width: 140 });
    expect(spec.width).toBe(176);
    expect(spec.minWidth).toBe(176);
    expect(fitMinWidth(spec)).toBe(176);
    const r = row({ visited_at: ISO });
    expect(spec.format?.(r)).toBe("2026-03-01 00:12:33");
    expect(spec.tooltip?.(r)).toContain("UTC");
    // A non-time column keeps its own width.
    expect(kindColumn({ header: "제목", keys: ["title"], width: 140 }).width).toBe(140);
  });

  it("every grid's 시각 columns share the fixed 176px width and zone-free text (timeline · search · review · files · analysis · family)", () => {
    const timeColumns = [
      timelineCollection,
      searchCollection,
      reviewCollection,
      analysisCollection,
      filesCollection,
    ].flatMap((collection) =>
      collection.columns.filter((c) => c.filterKind === "time" || c.id === "timestamp"),
    );
    const ids = timeColumns.map((c) => c.id);
    expect(ids).toEqual(expect.arrayContaining(["timestamp", "ntfsCreated"]));
    for (const column of timeColumns) {
      expect([column.id, column.width]).toEqual([column.id, TIME_COLUMN_WIDTH]);
      expect([column.id, column.minWidth]).toEqual([column.id, TIME_COLUMN_WIDTH]);
      expect(fitMinWidth(column)).toBe(TIME_COLUMN_WIDTH);
      expect(growWeight(column)).toBe(0);
    }
    const plain = row({});
    const timelineTime = timelineCollection.columns.find((c) => c.id === "timestamp");
    expect(timelineTime?.format?.(plain)).toMatch(WALL);
    const files = makeRow(makeRef("files", "/candidates/0"), { title: "a" }, { modifiedAt: ISO });
    const modified = filesCollection.columns.find((c) => c.id === "timestamp");
    expect(modified?.format?.(files)).toBe("2026-03-01 00:12:33");
    expect(modified?.tooltip?.(files)).toContain("UTC");
    // Family catalogue: a time-only column is 176px; one that can show a kind chip is 200px fixed.
    const visited = catalogColumn({ key: "visited_at", label: "방문", format: "time", ts_kind: "visit" });
    expect([visited.width, visited.minWidth]).toEqual([TIME_COLUMN_WIDTH, TIME_COLUMN_WIDTH]);
    const family = row({ visited_at: ISO });
    expect(visited.format?.(family)).toBe("2026-03-01 00:12:33");
    expect(visited.tooltip?.(family)).toContain("UTC");
    const chip = catalogColumn({ key: "timestamp", label: "시각", format: "time", ts_kind: "event" });
    expect([chip.width, chip.minWidth]).toEqual([TIME_CHIP_COLUMN_WIDTH, TIME_COLUMN_WIDTH]);
  });

  it("전체 아티팩트 날짜 및 시각 is 176px fixed with the zone-free time under its kind label", () => {
    const sumTime = mixedSummaryColumns().find((c) => c.id === "sum:time");
    expect([sumTime?.width, sumTime?.minWidth]).toEqual([TIME_COLUMN_WIDTH, TIME_COLUMN_WIDTH]);
    expect(sumTime && fitMinWidth(sumTime)).toBe(TIME_COLUMN_WIDTH);
    expect(sumTime && growWeight(sumTime)).toBe(0);
    const r = row({});
    expect(sumTime?.value?.(r)).toBe("2026-03-01 00:12:33");
    expect(sumTime?.tooltip?.(r)).toContain("UTC");
  });
  it("gridTimeText reads empty values as empty", () => {
    expect(gridTimeText(null, "utc")).toBe("");
    expect(gridTimeText("", "utc")).toBe("");
    expect(gridTimeText(ISO, "utc")).toBe("2026-03-01 00:12:33");
  });
});
