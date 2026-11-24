/**
 * D22 adversarial review #7 and #10 (D16 #12; synthetic values only): a wall clock converted under
 * an explicit evidence zone round-trips through the zone (a daylight-saving gap has no instant, a
 * repeated hour has two), and the analysis preset's 시각(기록) column exports the 100 ns record
 * time like the generic 시각 column.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { resetAppStore } from "../../state/store";
import { assumedUtcCandidates } from "../../utils/time";
import { FALLBACK_CATALOG, setCatalog } from "../flags/catalog";
import { artifactsCollection } from "../grid/columns/artifacts";
import { timelineCollection } from "../grid/columns/timeline";
import type { ColumnSpec } from "../grid/types";
import { buildSelectionCsv } from "./csv";

// The bundled catalogue (generated from the backend YAML): the eventlog family's 시각(기록).
beforeEach(() => setCatalog(FALLBACK_CATALOG, "fallback"));
afterEach(() => {
  setCatalog(null);
  resetAppStore();
});

function csvCells(csv: string): { header: string[]; rows: string[][] } {
  const lines = csv
    .replace(/^\uFEFF/, "")
    .trimEnd()
    .split("\r\n");
  return { header: lines[0]?.split(",") ?? [], rows: lines.slice(1).map((line) => line.split(",")) };
}

describe("D22 #7: explicit evidence zone on daylight-saving transition days", () => {
  it("New York wall clocks convert by round trip: one, none or two instants", () => {
    const zone = "America/New_York";
    expect(assumedUtcCandidates("2024-03-10 01:30:00", zone)).toEqual(["2024-03-10T06:30:00Z"]);
    // 02:30 on 10 March 2024 never happened in New York (clocks went 02:00 -> 03:00).
    expect(assumedUtcCandidates("2024-03-10 02:30:00", zone)).toEqual([]);
    expect(assumedUtcCandidates("2024-03-10 03:30:00", zone)).toEqual(["2024-03-10T07:30:00Z"]);
    expect(assumedUtcCandidates("2024-03-11 03:30:00", zone)).toEqual(["2024-03-11T07:30:00Z"]);
    // 01:30 on 3 November 2024 happened twice (EDT, then EST).
    expect(assumedUtcCandidates("2024-11-03 01:30:00", zone)).toEqual([
      "2024-11-03T05:30:00Z",
      "2024-11-03T06:30:00Z",
    ]);
    expect(assumedUtcCandidates("2024-03-10 03:30:00.1234567", zone)).toEqual([
      "2024-03-10T07:30:00.1234567Z",
    ]);
  });

  it("the selection CSV states the single instant, the gap and both repeated-hour candidates", () => {
    resetAppStore({
      route: { runId: "synthetic", collection: "timeline" },
      runs: [{ run_id: "synthetic", evidence_timezone: "America/New_York" }],
    } as never);
    const timeColumn = timelineCollection.columns[0];
    if (!timeColumn) throw new Error("timeline has no time column");
    const stamps = ["2024-03-10T02:30:00", "2024-03-10T03:30:00", "2024-11-03T01:30:00"];
    const rows = stamps.map((timestamp, index) =>
      timelineCollection.mapRow({ timestamp, timezone: "local-unknown", event_type: "registry" }, index, {
        ref: { id: "timeline" },
      }),
    );
    const { header, rows: lines } = csvCells(buildSelectionCsv(rows, [timeColumn], null));
    const assumed = lines.map((line) => line[header.indexOf("가정 환산 UTC (근거)")] ?? "");
    expect(assumed[0]).toContain("환산 불가");
    expect(assumed[0]).not.toMatch(/\d{2}:\d{2}:\d{2}Z/);
    expect(assumed[1]).toBe("2024-03-10T07:30:00Z (가정: 증거 시간대 America/New_York)");
    expect(assumed[2]).toContain("2024-11-03T05:30:00Z 또는 2024-11-03T06:30:00Z");
  });
});

// The event-log rows as the API hands them over: JSON-parsed (the tick numbers are rounded
// doubles), the 7-digit `timestamp_100ns` is the exact record time; no `event_created_at`, so the
// preset's 시각(기록) column reads its `timestamp` alias.
const EVTX_ROWS = JSON.parse(
  `[{"record_id":"50","channel":"Security","event_id":4624,"timestamp":"2024-01-01T00:00:00+00:00",
     "timestamp_100ns":"2024-01-01T00:00:00.0000007Z","timestamp_utc_ticks":133485408000000007},
    {"record_id":"51","channel":"Security","event_id":4624,"timestamp":"2024-01-01T00:00:00+00:00",
     "timestamp_100ns":"2024-01-01T00:00:00.0000001Z","timestamp_utc_ticks":133485408000000001}]`,
) as Record<string, unknown>[];

describe("D22 #10 (D16 #12): analysis preset 시각(기록) keeps the 100 ns record time", () => {
  const rows: GridRow[] = EVTX_ROWS.map((details, index) =>
    artifactsCollection.mapRow({ artifact_type: "eventlog-event", details }, index, {
      ref: { id: "artifacts", kind: "eventlog" },
    }),
  );
  const presetTime = (): ColumnSpec => {
    const columns =
      artifactsCollection.columnsFor?.({ id: "artifacts", kind: "eventlog" }, ["eventlog-event"]) ?? [];
    const column = columns.find((spec) => spec.header === "시각(기록)" && spec.presets.includes("analysis"));
    if (!column) throw new Error("eventlog analysis preset has no 시각(기록) column");
    return column;
  };

  it("selection CSV keeps the 7 and 1 ticks, exact UTC and FILETIME in every display zone", () => {
    for (const zone of ["utc", "Asia/Seoul", "America/New_York"]) {
      resetAppStore({ timezone: zone });
      const column = presetTime();
      const { header, rows: lines } = csvCells(buildSelectionCsv(rows, [column], null));
      const at = (name: string) => header.indexOf(name);
      expect(lines[0]?.[at("시각(기록)")]).toContain(".0000007");
      expect(lines[1]?.[at("시각(기록)")]).toContain(".0000001");
      expect(lines.map((line) => line[at("시각(기록) UTC 원문")])).toEqual([
        "2024-01-01T00:00:00.0000007Z",
        "2024-01-01T00:00:00.0000001Z",
      ]);
      expect(lines.map((line) => line[at("시각(기록) FILETIME")])).toEqual([
        "133485408000000007",
        "133485408000000001",
      ]);
      expect(lines.map((line) => line[at("시각(기록) 시간대 상태")])).toEqual([
        "UTC 기준 시각",
        "UTC 기준 시각",
      ]);
    }
  });

  it("client order compares integer ticks: #51 before #50", () => {
    const column = presetTime();
    const compare = column.compare;
    if (!compare) throw new Error("시각(기록) has no evidence-time order");
    const ordered = rows.slice().sort(compare);
    expect(ordered.map((row) => (row.fields.details as Record<string, unknown>).record_id)).toEqual([
      "51",
      "50",
    ]);
    expect(
      rows
        .slice()
        .sort((a, b) => -compare(a, b))
        .map((row) => (row.fields.details as Record<string, unknown>).record_id),
    ).toEqual(["50", "51"]);
  });
});
