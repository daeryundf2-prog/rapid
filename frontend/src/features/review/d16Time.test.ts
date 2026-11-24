/**
 * D16 adversarial review #12, #13 and #14 (with D12-5 / D14-11; synthetic values only): the
 * artifact grid reads an EVTX / LNK / DestList time from its 100 ns sibling, so the selection CSV
 * and the FILETIME tooltip keep the 1 and 7 tick digits, and the timeline "시각" sort compares
 * integer ticks (7 ticks before 10 ticks although ".000001" sorts before ".0000007" as text) with
 * undetermined-zone wall clocks kept apart from UTC instants.
 */

import { afterEach, describe, expect, it } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { resetAppStore } from "../../state/store";
import { evidenceTimeTooltip, preciseTimeOf, utcTicksOf } from "../../utils/time";
import { artifactRowTime, artifactsCollection } from "../grid/columns/artifacts";
import { col } from "../grid/columns/common";
import { timelineCollection } from "../grid/columns/timeline";
import { compareValues } from "../grid/gridUtils";
import type { ColumnSpec } from "../grid/types";
import { buildSelectionCsv } from "./csv";

afterEach(() => resetAppStore());

/** CSV data rows split into cells (no quoted commas in these fixtures). */
function csvCells(csv: string): { header: string[]; rows: string[][] } {
  const lines = csv
    .replace(/^\uFEFF/, "")
    .trimEnd()
    .split("\r\n");
  return { header: lines[0]?.split(",") ?? [], rows: lines.slice(1).map((line) => line.split(",")) };
}

/** Client order of `rows` by `spec`, as DataGrid sorts it (TanStack negates for descending). */
function sortedBy(spec: ColumnSpec, rows: GridRow[], desc = false): GridRow[] {
  const compare = spec.compare ?? ((a: GridRow, b: GridRow) => compareValues(spec.value(a), spec.value(b)));
  return rows.slice().sort((a, b) => (desc ? -1 : 1) * compare(a, b));
}

// The event-log provider row as the API hands it to the console: JSON-parsed, so the 18-digit
// tick numbers are already rounded doubles; the 7-digit text is the exact time.
const EVTX_ROWS = JSON.parse(
  `[{"record_id":"50","timestamp":"2024-01-01T00:00:00+00:00","timestamp_100ns":"2024-01-01T00:00:00.0000007Z",
     "timestamp_utc_ticks":133485408000000007,"timestamp_filetime":133485408000000007},
    {"record_id":"51","timestamp":"2024-01-01T00:00:00+00:00","timestamp_100ns":"2024-01-01T00:00:00.0000001Z",
     "timestamp_utc_ticks":133485408000000001,"timestamp_filetime":133485408000000001}]`,
) as Record<string, unknown>[];

describe("D16 #12 (D12-5, D14-11): artifact grid time keeps 100 ns ticks", () => {
  const rows = EVTX_ROWS.map((details, index) =>
    artifactsCollection.mapRow({ artifact_type: "eventlog-event", details }, index, {
      ref: { id: "artifacts", kind: "eventlog" },
    }),
  );

  it("row time is the 100 ns sibling of the same instant", () => {
    expect(rows.map((row) => row.timestamp)).toEqual([
      "2024-01-01T00:00:00.0000007Z",
      "2024-01-01T00:00:00.0000001Z",
    ]);
    // A sibling of another instant is not taken.
    expect(
      preciseTimeOf(
        { timestamp_100ns: "2024-01-01T00:00:01.0000007Z" },
        "timestamp",
        "2024-01-01T00:00:00+00:00",
      ),
    ).toBe("2024-01-01T00:00:00+00:00");
    // A wall clock (no offset) never takes a UTC sibling.
    expect(
      preciseTimeOf({ timestamp_100ns: "2024-01-01T00:00:00.0000007Z" }, "timestamp", "2024-01-01T00:00:00"),
    ).toBe("2024-01-01T00:00:00");
  });

  it("selection CSV has distinct exact UTC and FILETIME for #50 and #51 in every zone", () => {
    for (const zone of ["utc", "Asia/Seoul", "America/New_York"]) {
      resetAppStore({ timezone: zone });
      const { header, rows: lines } = csvCells(buildSelectionCsv(rows, [col.timestamp()], null));
      const at = (name: string) => header.indexOf(name);
      expect(lines.map((line) => line[at("시각 UTC 원문")])).toEqual([
        "2024-01-01T00:00:00.0000007Z",
        "2024-01-01T00:00:00.0000001Z",
      ]);
      expect(lines.map((line) => line[at("FILETIME")])).toEqual(["133485408000000007", "133485408000000001"]);
      expect(lines[0]?.[at("시각")]).toContain(".0000007");
      expect(lines[1]?.[at("시각")]).toContain(".0000001");
    }
  });

  it("the tooltip never shows the rounded JSON number as the FILETIME original", () => {
    const [first] = rows;
    if (!first?.timestamp) throw new Error("no row time");
    const tooltip = evidenceTimeTooltip(first.timestamp, "utc", EVTX_ROWS[0]?.timestamp_filetime as number);
    expect(tooltip).toContain("FILETIME(환산) 133485408000000007");
    expect(tooltip).not.toContain("133485408000000000");
  });

  it("the client order of the artifact time column is #51 then #50", () => {
    expect(sortedBy(col.timestamp(), rows).map((row) => row.timestamp)).toEqual([
      "2024-01-01T00:00:00.0000001Z",
      "2024-01-01T00:00:00.0000007Z",
    ]);
  });
});

describe("D16 #14: LNK and DestList times keep their FILETIME ticks in the grid", () => {
  it("recent-shortcut and jumplist-entry rows read target / DestList 100 ns siblings", () => {
    const lnk = {
      target_modified_at: "2024-01-01T00:00:00+00:00",
      target_modified_at_100ns: "2024-01-01T00:00:00.0000007Z",
    };
    expect(artifactRowTime(lnk)).toBe("2024-01-01T00:00:00.0000007Z");
    const jump = {
      timestamp: "2024-01-01T00:00:00+00:00",
      timestamp_100ns: "2024-01-01T00:00:00.0000001Z",
      destlist_last_modified_at_100ns: "2024-01-01T00:00:00.0000001Z",
    };
    expect(artifactRowTime(jump)).toBe("2024-01-01T00:00:00.0000001Z");
  });
});

describe("D16 #13: timeline 시각 sort compares integer ticks", () => {
  const timeColumn = timelineCollection.columns[0];
  if (!timeColumn) throw new Error("timeline has no time column");
  // Backend order: 7-tick EVTX event, then the 10-tick (1 µs) file modification.
  const events = [
    {
      timestamp: "2024-01-01T00:00:00.0000007+00:00",
      timezone: "UTC",
      event_type: "eventlog-logon-success",
      details: { timestamp_utc_ticks: "133485408000000007" },
    },
    {
      timestamp: "2024-01-01T00:00:00.000001+00:00",
      timezone: "UTC",
      event_type: "file-modified",
      details: { timestamp_utc_ticks: "133485408000000010" },
    },
  ];
  const rows = events.map((raw, index) => timelineCollection.mapRow(raw, index, { ref: { id: "timeline" } }));
  const wall = timelineCollection.mapRow(
    { timestamp: "2023-12-31T23:00:00", timezone: "local-unknown", event_type: "registry" },
    2,
    { ref: { id: "timeline" } },
  );

  it("ascending is 7 then 10 ticks and descending 10 then 7, whatever the fraction length", () => {
    expect(utcTicksOf(events[0]?.timestamp)?.ticks).toBe(133485408000000007n);
    expect(utcTicksOf(events[1]?.timestamp)?.ticks).toBe(133485408000000010n);
    expect(sortedBy(timeColumn, [rows[1], rows[0]] as GridRow[]).map((row) => row.timestamp)).toEqual([
      events[0]?.timestamp,
      events[1]?.timestamp,
    ]);
    expect(sortedBy(timeColumn, rows, true).map((row) => row.timestamp)).toEqual([
      events[1]?.timestamp,
      events[0]?.timestamp,
    ]);
  });

  it("an undetermined-zone wall clock is never ordered among UTC instants", () => {
    // As UTC text 23:00 on Dec 31 would sort first; it is a group of its own after the instants.
    expect(sortedBy(timeColumn, [wall, ...rows]).map((row) => row.timestamp)).toEqual([
      events[0]?.timestamp,
      events[1]?.timestamp,
      "2023-12-31T23:00:00",
    ]);
  });
});
