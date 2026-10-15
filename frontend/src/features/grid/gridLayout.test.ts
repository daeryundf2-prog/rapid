import { describe, expect, it } from "vitest";
import { ARTIFACT_PRIORITY } from "./columns/artifacts";
import { FILES_PRIORITY } from "./columns/files";
import { fitColumnWidths, priorityHiddenColumns } from "./gridUtils";

describe("fitColumnWidths (항목 flexes; nothing shrinks)", () => {
  const base = [140, 130, 220, 200, 88]; // 시각 · 유형 · 항목 · 경로 · 선별

  it("gives the slack to the flexing column", () => {
    const out = fitColumnWidths(base, { grow: 2, available: 1000 });
    expect(out).toEqual([140, 130, 442, 200, 88]);
    expect(out.reduce((a, b) => a + b, 0)).toBe(1000);
  });

  it("never shrinks a column when the pane is narrower (the grid scrolls instead)", () => {
    expect(fitColumnWidths(base, { grow: 2, available: 500 })).toEqual(base);
  });

  it("leaves widths alone before the pane is measured or when 항목 was resized", () => {
    expect(fitColumnWidths(base, { grow: 2, available: 0 })).toEqual(base);
    expect(fitColumnWidths(base, { grow: -1, available: 1000 })).toEqual(base);
  });
});

describe("priorityHiddenColumns (responsive default columns)", () => {
  const artifacts = [
    { id: "timestamp", min: 140 },
    { id: "type", min: 130 },
    { id: "title", min: 220 },
    { id: "path", min: 200 },
    { id: "review", min: 88 },
  ]; // Σ 778
  const files = [
    { id: "title", min: 220 },
    { id: "path", min: 200 },
    { id: "size", min: 80 },
    { id: "timestamp", min: 150 },
    { id: "ntfsCreated", min: 150 },
    { id: "review", min: 88 },
  ]; // Σ 888
  const hide = (cols: typeof artifacts, available: number, keep?: Set<string>) =>
    priorityHiddenColumns(cols, { priority: ARTIFACT_PRIORITY, available, keep });

  it("hides nothing when the minimums fit, or before the grid is measured", () => {
    expect(hide(artifacts, 778)).toEqual([]);
    expect(hide(artifacts, 0)).toEqual([]);
  });

  it("drops artifacts columns lowest priority first: 경로, 선별, 시각, 유형", () => {
    expect(hide(artifacts, 700)).toEqual(["path"]);
    expect(hide(artifacts, 576)).toEqual(["path", "review"]);
    expect(hide(artifacts, 400)).toEqual(["path", "review", "timestamp"]);
    // 항목 always stays, even when it alone does not fit.
    expect(hide(artifacts, 100)).toEqual(["path", "review", "timestamp", "type"]);
  });

  it("drops files columns by 이름 > 수정 > 크기 > 선별 > 경로 > NTFS 생성", () => {
    const out = (available: number) => priorityHiddenColumns(files, { priority: FILES_PRIORITY, available });
    expect(out(800)).toEqual(["ntfsCreated"]);
    expect(out(600)).toEqual(["ntfsCreated", "path"]);
    expect(out(450)).toEqual(["ntfsCreated", "path", "review"]);
    expect(out(300)).toEqual(["ntfsCreated", "path", "review", "size", "timestamp"]);
  });

  it("keeps pinned columns and never hides columns outside the priority list", () => {
    expect(hide(artifacts, 576, new Set(["path"]))).toEqual(["review", "timestamp"]);
    const extra = [...artifacts, { id: "field:foo", min: 150 }];
    expect(hide(extra, 778)).toEqual(["path"]);
  });

  it("skips priority ids that are not visible (hidden by the user)", () => {
    const noPath = artifacts.filter((c) => c.id !== "path");
    expect(hide(noPath, 576)).toEqual(["review"]);
  });
});
