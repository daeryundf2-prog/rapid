/**
 * T-175 (r8 design system "시각 열 176px 고정", IS-020 / QA-044): the artifacts 시각 column and the
 * kind time columns are 176px wide, neither grow nor shrink below that, and their cell text is
 * "YYYY-MM-DD HH:MM:SS" (the zone is in the tooltip), so the cell never truncates.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GridRow } from "../../../contracts/collection";
import { useAppStore } from "../../../state/store";
import { artifactsCollection, kindColumn } from "./artifacts";
import { fitMinWidth, growWeight, makeRef, makeRow } from "./common";
import { gridTimeText, TIME_COLUMN_WIDTH } from "./TimelineCells";

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

  it("gridTimeText reads empty values as empty", () => {
    expect(gridTimeText(null, "utc")).toBe("");
    expect(gridTimeText("", "utc")).toBe("");
    expect(gridTimeText(ISO, "utc")).toBe("2026-03-01 00:12:33");
  });
});
