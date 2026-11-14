import { describe, expect, it } from "vitest";
import { chipToneOf } from "../../components/ToneChip";
import type { GridRow } from "../../contracts/collection";
import { artifactTypeLabel, typeOptionsFor } from "../filters/typeLabels";
import { BATCH_BAR_MIN, batchBarState } from "./BatchBar";
import { makeRef, makeRow } from "./columns/common";
import { outputDisplayName } from "./columns/outputs";
import { OTHER_TYPE_COLOUR, typeColourIndex } from "./columns/StatusCells";
import { emptyColumnIds } from "./gridUtils";
import { rowMenuShortcut } from "./RowMenu";
import type { ColumnSpec } from "./types";

const keys = (...k: string[]) => new Set(k);

describe("batch bar threshold (review #2)", () => {
  const all = () => true;
  it("needs two selected rows; one row is the viewer's job", () => {
    expect(BATCH_BAR_MIN).toBe(2);
    expect(batchBarState(keys(), all)).toEqual({ visible: false, count: 0 });
    expect(batchBarState(keys("a"), all)).toEqual({ visible: false, count: 1 });
    expect(batchBarState(keys("a", "b"), all)).toEqual({ visible: true, count: 2 });
  });

  it("an open tag prompt keeps a one-row bar up (T on a single row)", () => {
    expect(batchBarState(keys("a"), all, true)).toEqual({ visible: true, count: 1 });
    expect(batchBarState(keys(), all, true).visible).toBe(false);
  });

  it("hides once the filtered rows no longer contain the selection", () => {
    const onScreen = (k: string) => k === "c";
    expect(batchBarState(keys("a", "b"), onScreen).visible).toBe(false);
    // Still on screen in part: the bar stays and counts the whole selection it acts on.
    expect(batchBarState(keys("a", "c"), onScreen)).toEqual({ visible: true, count: 2 });
  });
});

const row = (fields: Partial<GridRow>, index: number): GridRow =>
  makeRow(makeRef("files", `/candidates/${index}`), { title: `f${index}`, ...fields });

const spec = (id: string, value: (r: GridRow) => unknown, extra: Partial<ColumnSpec> = {}): ColumnSpec => ({
  id,
  header: id,
  width: 100,
  presets: ["analysis"],
  value: value as ColumnSpec["value"],
  ...extra,
});

describe("auto-hide empty default columns (review #9)", () => {
  const columns = [
    spec("title", (r) => r.title),
    spec("timestamp", (r) => r.timestamp),
    spec("review", (r) => r.reviewStatus),
    spec("tags", (r) => r.tags),
    spec("ntfs", () => null, {
      emptyHint: { text: "NTFS 메타를 실행하세요", command: "x", commandLabel: "실행" },
    }),
  ];
  const candidates = ["timestamp", "review", "tags", "ntfs"];

  it("hides a candidate whose every loaded row is empty (null, blank, empty list)", () => {
    const rows = [row({ timestamp: " " }, 0), row({}, 1)];
    expect(emptyColumnIds(columns, rows, { candidates })).toEqual(["timestamp", "review", "tags"]);
  });

  it("keeps a column as soon as one row has a value", () => {
    const rows = [row({ reviewStatus: "relevant", timestamp: "2026-01-01T00:00:00Z" }, 0), row({}, 1)];
    expect(emptyColumnIds(columns, rows, { candidates })).toEqual(["tags"]);
  });

  it("never hides before rows load, a column the user showed, a hinted column or a non-candidate", () => {
    expect(emptyColumnIds(columns, [], { candidates })).toEqual([]);
    const rows = [row({}, 0)];
    expect(emptyColumnIds(columns, rows, { candidates, keep: keys("review") })).toEqual([
      "timestamp",
      "tags",
    ]);
    expect(emptyColumnIds(columns, rows, { candidates: ["title", "ntfs"] })).toEqual([]);
  });
});

describe("status chip mapping (review #11 / #24)", () => {
  it("maps job / run / file states onto the chip tones", () => {
    expect(chipToneOf("completed")).toBe("ok");
    expect(chipToneOf("failed")).toBe("danger");
    expect(chipToneOf("missing")).toBe("danger");
    expect(chipToneOf("cancelled")).toBe("warn");
    expect(chipToneOf("canceled")).toBe("warn");
    expect(chipToneOf("partial")).toBe("warn");
    expect(chipToneOf("running")).toBe("info");
    expect(chipToneOf("queued")).toBe("info");
    expect(chipToneOf("RUNNING")).toBe("info");
    expect(chipToneOf(null)).toBe("");
    expect(chipToneOf("whatever")).toBe("");
  });
});

describe("type dot colours (review #9)", () => {
  it("spreads real types over tag-1…7 and reserves tag-8 for catch-all types", () => {
    for (const type of ["browser-history", "windows-prefetch", "media-image", "a", "zzzz-long-type-name"]) {
      const n = typeColourIndex(type);
      expect(n).toBeGreaterThanOrEqual(1);
      expect(n).toBeLessThanOrEqual(7);
      expect(typeColourIndex(type)).toBe(n);
    }
    expect(OTHER_TYPE_COLOUR).toBe(8);
    for (const other of ["other", "Unknown", "기타"]) expect(typeColourIndex(other)).toBe(8);
  });
});

describe("보고 table names (review #9)", () => {
  it("reads raw output keys as Korean names", () => {
    // C-P1: the kind's Korean family name + the file name (the raw key stays the tooltip).
    const named = outputDisplayName(
      "artifacts_windows-prefetch",
      "D:/out/rapidtriage-artifacts-windows-prefetch.json",
    );
    expect(named).toMatch(/ — rapidtriage-artifacts-windows-prefetch\.json$/);
    expect(named).not.toMatch(/artifacts_|windows-prefetch —/);
    expect(outputDisplayName("artifacts_android-apk")).not.toContain("아티팩트: ");
    expect(outputDisplayName("carve_extract_manifest")).toBe("추출 매니페스트: carve");
    expect(outputDisplayName("docs_index")).toBe("문서 색인");
    expect(outputDisplayName("case_db")).toBe("케이스 DB");
    expect(outputDisplayName("something_new")).toBe("something_new");
    expect(outputDisplayName("artifacts_")).toBe("artifacts_");
  });
});

describe("유형 filter list (review #10)", () => {
  it("names the types the domain tree names and searches label or id", () => {
    expect(artifactTypeLabel("task-scheduler-task")).toBe("작업 스케줄러");
    expect(artifactTypeLabel("no-such-type")).toBeNull();
    const options = typeOptionsFor(["task-scheduler-task", "browser-x"], { "browser-x": 4 });
    expect(options).toEqual([
      { id: "task-scheduler-task", label: "작업 스케줄러", count: undefined },
      { id: "browser-x", label: null, count: 4 },
    ]);
    expect(typeOptionsFor(["task-scheduler-task", "browser-x"], {}, "스케줄").map((o) => o.id)).toEqual([
      "task-scheduler-task",
    ]);
    expect(typeOptionsFor(["task-scheduler-task", "browser-x"], {}, "BROWSER").map((o) => o.id)).toEqual([
      "browser-x",
    ]);
  });
});

describe("row menu key hints (review #13)", () => {
  it("come from the key map: Enter opens, R / X / I / B mark, others have none", () => {
    expect(rowMenuShortcut("grid.openSource")).toBe("Enter");
    expect(rowMenuShortcut("grid.row.relevant")).toBe("R");
    expect(rowMenuShortcut("grid.row.excluded")).toBe("X");
    expect(rowMenuShortcut("grid.row.needs-review")).toBe("I");
    expect(rowMenuShortcut("grid.row.bookmark")).toBe("B");
    expect(rowMenuShortcut("grid.row.include-in-report")).toBeUndefined();
    expect(rowMenuShortcut("grid.copyPath")).toBeUndefined();
    expect(rowMenuShortcut("grid.copyPath", "Ctrl+C")).toBe("Ctrl+C");
  });
});
