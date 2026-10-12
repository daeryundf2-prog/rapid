import { describe, expect, it } from "vitest";
import { fitColumnWidths, splitPathTail } from "./gridUtils";

describe("fitColumnWidths (항목 flexes, 경로/항목 shrink to fit — visual-polish B2 #2)", () => {
  const base = [140, 120, 240, 220, 88]; // 시각 · 유형 · 항목 · 경로 · 선별
  const mins = [60, 60, 120, 100, 60];
  const shrinkable = [false, false, true, true, false];

  it("gives the slack to the flexing column", () => {
    const out = fitColumnWidths(base, { grow: 2, shrinkable, mins, available: 1000 });
    expect(out).toEqual([140, 120, 432, 220, 88]);
    expect(out.reduce((a, b) => a + b, 0)).toBe(1000);
  });

  it("shrinks only the shrinkable columns, never below their minimum", () => {
    // ~1440px viewport: grid pane ≈ 676px − select 56 − tools 40.
    const out = fitColumnWidths(base, { grow: 2, shrinkable, mins, available: 580 });
    expect(out.slice(0, 2)).toEqual([140, 120]);
    expect(out[4]).toBe(88);
    expect(out[2]).toBeGreaterThanOrEqual(120);
    expect(out[3]).toBeGreaterThanOrEqual(100);
    expect(out.reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(581);
  });

  it("stops at the minimums when the pane is too narrow (the grid scrolls)", () => {
    const out = fitColumnWidths(base, { grow: 2, shrinkable, mins, available: 300 });
    expect(out).toEqual([140, 120, 120, 100, 88]);
  });

  it("leaves widths alone before the pane is measured", () => {
    expect(fitColumnWidths(base, { grow: 2, shrinkable, mins, available: 0 })).toEqual(base);
  });
});

describe("splitPathTail (경로 truncates in the middle)", () => {
  it("keeps the file name whole", () => {
    expect(splitPathTail("C:\\a\\b\\messages.json")).toEqual(["C:\\a\\b\\", "messages.json"]);
    expect(splitPathTail("/var/log/syslog")).toEqual(["/var/log/", "syslog"]);
    expect(splitPathTail("file.txt")).toEqual(["", "file.txt"]);
    expect(splitPathTail("C:\\dir\\")).toEqual(["", "C:\\dir\\"]);
  });
});
