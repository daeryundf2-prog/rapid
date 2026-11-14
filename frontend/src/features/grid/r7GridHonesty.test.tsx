// R7 stage 1 lane L2 (plan r7 §3.2): grid columns, paths and range honesty — unit checks.
import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { DOCS_MATCHED, DOCS_UNMATCHED, filesOrderQueryString } from "../../api/collections";
import { MiddlePath } from "../../components/MiddlePath";
import { placePopover } from "../../components/Popover";
import { shouldAutoFoldTree, TREE_AUTOFOLD_BELOW } from "../../shell/Layout";
import { presetColumnIds } from "./columns";
import { growWeight, TIME_COLUMN_MIN } from "./columns/common";
import { docsCollection, docsColumnsFor } from "./columns/docs";
import { filesCollection, filesServerSort, runInputIsImage } from "./columns/files";
import { indicatorsCollection } from "./columns/indicators";
import { reviewCollection } from "./columns/review";
import { timelineCollection } from "./columns/timeline";
import { fitColumnWidths } from "./gridUtils";
import { serverSortOf } from "./useCollectionQuery";

afterEach(cleanup);

describe("files server sort / text filter (C-D1)", () => {
  it("indexed columns carry the server's sort keys; others stay client-side", () => {
    const keys = Object.fromEntries(filesCollection.columns.map((c) => [c.id, c.sortKey]));
    expect(keys).toMatchObject({
      title: "name",
      path: "path",
      size: "size",
      timestamp: "mtime",
      ntfsCreated: "ctime",
      flags: "flags",
    });
    expect(keys.extension).toBeUndefined();
    const query = { ref: { id: "files" as const }, offset: 0, limit: 250 };
    expect(serverSortOf({ ...query, sort: { key: "size", order: "desc" } })).toEqual({
      key: "size",
      order: "desc",
    });
    expect(filesServerSort({ ...query, sort: { key: "extension", order: "asc" } })).toBeUndefined();
    expect(filesOrderQueryString({ sort: { key: "size", order: "desc" }, q: " 계약 서 " })).toBe(
      "&sort=size&order=desc&q=%EA%B3%84%EC%95%BD+%EC%84%9C",
    );
    expect(filesOrderQueryString({})).toBe("");
  });
});

describe("column widths (C-D6, C-D7, C-D14)", () => {
  it("time columns are at least 180px; 시각 종류 is 140px", () => {
    const time = filesCollection.columns.filter((c) => c.filterKind === "time");
    expect(time.length).toBeGreaterThan(2);
    for (const column of time)
      expect(column.minWidth ?? column.width).toBeGreaterThanOrEqual(TIME_COLUMN_MIN);
    const tsKind = timelineCollection.columns.find((c) => c.id === "tsKind");
    expect(tsKind?.width).toBe(140);
    const reviewTime = reviewCollection.columns.find((c) => c.id === "timestamp");
    expect(reviewTime?.minWidth).toBeGreaterThanOrEqual(TIME_COLUMN_MIN);
  });

  it("spare width goes to 항목 / 경로 / URL by weight, never to time or number columns", () => {
    expect(growWeight({ id: "title", header: "이름" })).toBe(3);
    expect(growWeight({ id: "path", header: "경로" })).toBe(2);
    expect(growWeight({ id: "d:url", header: "URL" })).toBe(2);
    expect(growWeight({ id: "d:title", header: "제목" })).toBe(1);
    expect(growWeight({ id: "timestamp", header: "수정", filterKind: "time" })).toBe(0);
    expect(growWeight({ id: "size", header: "크기", align: "right" })).toBe(0);
    // 100px slack over weights 3 · 0 · 2: 60 + 40; widths never shrink.
    expect(fitColumnWidths([220, 180, 200], { grow: 0, available: 700, weights: [3, 0, 2] })).toEqual([
      280, 180, 240,
    ]);
    expect(fitColumnWidths([220, 180, 200], { grow: 0, available: 500, weights: [3, 0, 2] })).toEqual([
      220, 180, 200,
    ]);
    // Too wide with minimums (r7 S1, browser kind at 1920): weight-0 columns give their room
    // above the minimum first (by room), the long-text ones keep their width.
    expect(
      fitColumnWidths([240, 150, 150, 200], {
        grow: 0,
        available: 640,
        weights: [3, 0, 0, 2],
        mins: [120, 60, 100, 200],
      }),
    ).toEqual([240, 85, 115, 200]);
    // More excess than the fixed columns hold: the text columns shrink too, never below minimum.
    expect(
      fitColumnWidths([240, 150, 200], { grow: 0, available: 480, weights: [3, 0, 2], mins: [120, 60, 200] }),
    ).toEqual([220, 60, 200]);
    // Even the minimums do not fit: everything at minimum, the grid scrolls.
    expect(
      fitColumnWidths([240, 150, 200], { grow: 0, available: 300, weights: [3, 0, 2], mins: [120, 60, 200] }),
    ).toEqual([120, 60, 200]);
    // No mins: never shrunk (the pre-r7 contract for callers without minimums).
    expect(fitColumnWidths([240, 150], { grow: 0, available: 300 })).toEqual([240, 150]);
    // No weights: the old single grow column.
    expect(fitColumnWidths([100, 100], { grow: 1, available: 250 })).toEqual([100, 150]);
  });

  it("timeline priority beside the viewer: 시각 > 대상 > 시각 종류 > 상세 (C-D15)", () => {
    expect(timelineCollection.widthPriority?.({ id: "timeline" })?.slice(0, 4)).toEqual([
      "timestamp",
      "target",
      "tsKind",
      "detail",
    ]);
  });
});

describe("column names and listings (C-D10, C-D11, C-D12)", () => {
  it("the review column reads 검토; the indicator classification column reads 범위", () => {
    expect(filesCollection.columns.find((c) => c.id === "review")?.header).toBe("검토");
    expect(indicatorsCollection.columns.find((c) => c.id === "review")?.header).toBe("검토");
    expect(indicatorsCollection.columns.find((c) => c.id === "classification")?.header).toBe("범위");
  });

  it("docs match columns are default columns only under 일치만", () => {
    const matched = presetColumnIds(docsColumnsFor(DOCS_MATCHED), "analysis");
    expect(matched).toEqual(expect.arrayContaining(["matched", "keywords"]));
    for (const category of [undefined, DOCS_UNMATCHED]) {
      const ids = presetColumnIds(docsColumnsFor(category), "analysis");
      expect(ids).not.toContain("matched");
      expect(ids).not.toContain("keywords");
      // Still selectable from 열 설정.
      expect(docsColumnsFor(category).map((c) => c.id)).toEqual(docsCollection.columns.map((c) => c.id));
    }
  });

  it("NTFS-meta can only run on an image input", () => {
    expect(runInputIsImage({ request: { root: "D:/evidence/disk.E01" } })).toBe(true);
    expect(runInputIsImage({ request: { root: "D:\\evidence\\disk.vhdx" } })).toBe(true);
    expect(runInputIsImage({ summary: { source: { type: "raw-image" } }, request: { root: "x" } })).toBe(
      true,
    );
    expect(runInputIsImage({ summary: { source: { type: "folder" } }, request: { root: "D:/x.E01" } })).toBe(
      false,
    );
    expect(runInputIsImage({ request: { root: "D:/rapid-qa/bsh-subset" } })).toBe(false);
    expect(runInputIsImage(null)).toBe(false);
  });
});

describe("MiddlePath tail first (C-D8, C-W6, C-L3)", () => {
  it("the text always holds the file name and two parents; the full path is the tooltip", () => {
    const path = "D:\\rapid-qa\\bsh-subset\\Users\\user\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat";
    const { container } = render(<MiddlePath path={path} />);
    const root = container.querySelector(".mid-path") as HTMLElement;
    expect(root.getAttribute("title")).toBe(path);
    expect(root.textContent).toBe(path);
    expect(root.querySelector(".mid-path-tail")?.textContent).toBe("UsrClass.dat");
    expect(root.querySelector(".mid-path-parents")?.textContent).toBe("Microsoft\\Windows\\");
    expect(root.querySelector(".mid-path-head")?.textContent).toBe(
      "D:\\rapid-qa\\bsh-subset\\Users\\user\\AppData\\Local\\",
    );
  });

  it("an evidence root (whole) uses the same tail-first layout", () => {
    const { container } = render(<MiddlePath path="D:\rapid-qa\bsh-subset" whole />);
    const root = container.querySelector(".mid-path") as HTMLElement;
    expect(root.classList.contains("mid-path-whole")).toBe(true);
    expect(root.querySelector(".mid-path-tail")?.textContent).toBe("bsh-subset");
  });
});

describe("조건 popover placement (C-D4)", () => {
  const viewport = { width: 1280, height: 720 };
  it("opens below the trigger and stays inside the viewport horizontally", () => {
    const place = placePopover(
      { top: 100, bottom: 128, left: 1100, right: 1160 },
      { width: 400, height: 300 },
      viewport,
      "start",
    );
    expect(place.above).toBe(false);
    expect(place.top).toBe(132);
    expect(place.left).toBe(1280 - 8 - 400);
  });

  it("flips above when the room below is short and there is more above", () => {
    const place = placePopover(
      { top: 600, bottom: 628, left: 200, right: 260 },
      { width: 400, height: 500 },
      viewport,
      "start",
    );
    expect(place.above).toBe(true);
    expect(place.top + Math.min(500, place.maxHeight)).toBeLessThanOrEqual(600);
    expect(place.top).toBeGreaterThanOrEqual(8);
    expect(place.left).toBe(200);
  });
});

describe("tree auto-fold policy (구조 D3)", () => {
  it("folds the tree for an opened viewer below 1600px only", () => {
    expect(TREE_AUTOFOLD_BELOW).toBe(1600);
    expect(shouldAutoFoldTree(1280)).toBe(true);
    expect(shouldAutoFoldTree(1440)).toBe(true);
    expect(shouldAutoFoldTree(1920)).toBe(false);
    expect(shouldAutoFoldTree(0)).toBe(false);
  });
});
