import { describe, expect, it } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { relatedSelection, relationReason, rowsSelection, type SelectionProfile } from "./actionApi";
import { summarize } from "./summary";

function row(partial: Partial<GridRow> & Pick<GridRow, "ref">): GridRow {
  return {
    rowKey: `${partial.ref.collection}:${partial.ref.locator}`,
    title: "행",
    sourcePath: null,
    timestamp: null,
    artifactType: null,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: {},
    ...partial,
  };
}

describe("action selections", () => {
  it("a timeline row anchors on the server; other rows send their own time or path", () => {
    const event = row({
      ref: { collection: "timeline", locator: "/events/12" },
      timestamp: "2026-04-18T05:30:00Z",
    });
    expect(relatedSelection(event, "time_window", 300)).toEqual({
      related: {
        relation: "time_window",
        anchor: { collection: "timeline", locator: "/events/12" },
        window_s: 300,
      },
    });
    expect(relatedSelection(event, "same_path", 300)).toEqual({
      related: { relation: "same_path", anchor: { collection: "timeline", locator: "/events/12" } },
    });
    const file = row({ ref: { collection: "files", locator: "/candidates/3" }, sourcePath: "C:\\a\\b.txt" });
    expect(relatedSelection(file, "same_name", 60)).toEqual({
      related: { relation: "same_name", path: "C:\\a\\b.txt" },
    });
    expect(relatedSelection(file, "time_window", 60)).toBeNull();
    expect(relationReason(file, "time_window")).toBe("이 행에는 시각이 없습니다");
    expect(relationReason(file, "same_path")).toBeUndefined();
  });

  it("explicit rows keep their run-output locators", () => {
    const selection = rowsSelection([
      row({ ref: { collection: "timeline", locator: "/events/1" } }),
      row({ ref: { collection: "artifacts", kind: "browser", locator: "/artifacts/4" } }),
    ]);
    expect(selection.rows).toEqual([
      { collection: "timeline", locator: "/events/1" },
      { collection: "artifacts", kind: "browser", locator: "/artifacts/4" },
    ]);
  });
});

describe("selection summary", () => {
  const profile: SelectionProfile = {
    total: 18,
    limit: 10000,
    over_limit: false,
    by_collection: { timeline: 18 },
    timeline_rows: 18,
    time_range: { first: "2026-04-18T05:01:07Z", last: "2026-04-18T05:57:58Z" },
    by_source: { files: 4, artifacts: 14 },
    by_event_type: { "file-created": 4 },
    top_paths: [{ path: "C:\\x.pdf", count: 2 }],
    sample: [{ locator: "/events/1", timestamp: null, event_type: null, summary: "File created: x.pdf" }],
  };

  it("lists count, span, sources by count, events, paths and samples in that order", () => {
    const lines = summarize(profile);
    expect(lines.map((line) => line.label)).toEqual([
      "건수",
      "기간",
      "출처",
      "이벤트",
      "자주 나온 경로",
      "예시",
    ]);
    expect(lines[0]?.value).toBe("18건");
    expect(lines[2]?.value).toBe("아티팩트 14 · 파일 4");
  });

  it("names each collection when the selection spans several", () => {
    const mixed = summarize({
      ...profile,
      total: 3,
      by_collection: { timeline: 1, files: 2 },
      time_range: null,
      by_source: {},
      by_event_type: {},
      top_paths: [],
      sample: [],
    });
    expect(mixed).toEqual([{ label: "건수", value: "3건 (파일 2 · 타임라인 1)" }]);
  });
});
