import { afterEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../contracts/collection";
import type { ViewerTarget } from "../../contracts/viewer";
import { useSearchState } from "../case/searchState";
import { countPivot, resetPivotCounts, SEARCH_LIST_LIMIT } from "./pivotCounts";
import { recordPivots } from "./pivots";
import { FILE_LEVEL_ONLY, hasRecordHead, plainTitle, recordHeadModel } from "./recordHeadModel";

const base = (patch: Partial<GridRow>): GridRow => ({
  rowKey: "k",
  ref: { collection: "timeline", locator: "/events/0" },
  title: "Artifact event: browser-history https://bank.example.test/account (합성 0)",
  sourcePath: "C:/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History",
  timestamp: "2026-10-17T23:02:48+00:00",
  artifactType: "artifact-browser-history-last-visited",
  provider: "artifacts",
  sha256: null,
  reviewStatus: null,
  tags: [],
  fields: {},
  ...patch,
});

const timelineRow = base({
  fields: { tsKind: "last-visited", sourceRecord: { output: "artifacts_browser", row_index: 2 } },
});

const decoded = base({
  rowKey: "a",
  ref: { collection: "artifacts", kind: "browser", locator: "/artifacts/2" },
  artifactType: "browser-history",
  fields: {
    details: {
      url: "https://bank.example.test/account",
      title: "Sample Bank Account",
      source_table: "urls",
      source_row_id: 1,
    },
  },
});

const target = (row: GridRow): ViewerTarget => ({ ref: row.ref, runId: "r1", sourcePath: row.sourcePath });

afterEach(() => {
  vi.unstubAllGlobals();
  resetPivotCounts();
});

describe("레코드 요약 (F18)", () => {
  it("is for artifact rows and timeline events with a source record", () => {
    expect(hasRecordHead(timelineRow, "r1")).toBe(true);
    expect(hasRecordHead(base({ fields: {} }), "r1")).toBe(false);
    expect(hasRecordHead(decoded, "r1")).toBe(true);
    expect(plainTitle(timelineRow.title)).toBe("https://bank.example.test/account (합성 0)");
  });

  it("names the target, what the time means, the source and the record locator", () => {
    const model = recordHeadModel(timelineRow, decoded, target(timelineRow), "utc", false);
    expect(model.target).toBe("https://bank.example.test/account");
    expect(model.time?.label).toBe("마지막 방문 시각");
    expect(model.time?.text).toContain("2026-10-17 23:02:48");
    expect(model.sourcePath).toContain("Default/History");
    expect(model.locator).toEqual([
      "레코드=원본 행 ID 1",
      "원본 레코드=artifacts_browser #2",
      "SQLite urls 테이블 행 id 1",
    ]);
    // SQLite view not available for this file: 원본 위치 열기 opens the source artifact row.
    expect(model.open).toMatchObject({ kind: "route", route: { collection: "artifacts", kind: "browser" } });
    expect(recordHeadModel(timelineRow, decoded, target(timelineRow), "utc", true).open).toEqual({
      kind: "sqlite",
      table: "urls",
      rowid: 1,
    });
  });

  it("opens hex at the record bytes, and says 파일 단위까지 추적 when no locator exists", () => {
    const evtx = base({
      ref: { collection: "artifacts", kind: "eventlog", locator: "/artifacts/9" },
      fields: { details: { record_offset: 4096, record_size: 120 } },
    });
    const withBytes = recordHeadModel(evtx, null, target(evtx), "utc");
    expect(withBytes.open).toEqual({ kind: "hex", offset: 4096, length: 120 });
    expect(withBytes.locator).toContain("바이트=0x00001000-0x00001077");
    const bare = base({ ref: { collection: "artifacts", kind: "x", locator: "/artifacts/1" }, fields: {} });
    const model = recordHeadModel(bare, null, target(bare), "utc");
    expect(model.locator).toEqual([]);
    expect(model.open).toBeNull();
    expect(FILE_LEVEL_ONLY).toBe("파일 단위까지 추적");
  });
});

describe("같은 대상 count (F19)", () => {
  it("counts with the same search request the opened list makes (URL target, not the limit-1 summary)", async () => {
    useSearchState.getState().resetOptions();
    const urls: URL[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string) => {
        urls.push(new URL(String(input), "http://x"));
        const matches = Array.from({ length: 62 }, (_, i) => ({ id: i }));
        return new Response(JSON.stringify({ matches, summary: { match_count: 62 }, backend: "fts" }), {
          headers: { "content-type": "application/json" },
        });
      }),
    );
    const pivot = recordPivots(timelineRow, "r1", "utc", decoded).find((p) => p.id === "same-target");
    expect(pivot?.route).toMatchObject({ collection: "search", q: "https://bank.example.test/account" });
    const count = await countPivot(pivot as never, timelineRow, "r1", new AbortController().signal);
    expect(count).toEqual({ count: 62, capped: false });
    expect(urls[0]?.searchParams.getAll("keyword")).toEqual(["https://bank.example.test/account"]);
    expect(urls[0]?.searchParams.get("limit")).toBe(String(SEARCH_LIST_LIMIT));
  });
});

describe("같은 원본 파일 count on the timeline (review P3-5)", () => {
  it("counts by the list's rule: the event path or its fallbacks, case-insensitive substring", async () => {
    const history = "C:/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History";
    const events = [
      { path: history },
      { path: `${history}-journal` },
      { details: { source_path: history.toUpperCase() } },
      { input_file: history },
      { path: "C:/other.log" },
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ events, pagination: { has_more: false } }), {
            headers: { "content-type": "application/json" },
          }),
      ),
    );
    const pivot = recordPivots(timelineRow, "r1", "utc", decoded).find((p) => p.id === "same-source");
    expect(pivot).toBeDefined();
    const count = await countPivot(pivot as never, timelineRow, "r1", new AbortController().signal);
    expect(count).toEqual({ count: 4, capped: false });
  });
});
