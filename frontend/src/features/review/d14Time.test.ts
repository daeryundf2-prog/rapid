/**
 * D14 adversarial review #8 and #11 (synthetic values only): the selection CSV and the FILETIME
 * tooltip share one lossless reading. A wall clock of undetermined zone keeps its written value in
 * every display zone, and 100 ns ticks (…0001 vs …0007) stay distinct and ordered.
 */

import { afterEach, describe, expect, it } from "vitest";
import { resetAppStore } from "../../state/store";
import { assumedUtcOfWallClock, evidenceTimeTooltip, exactEvidenceTime } from "../../utils/time";
import { col, makeRef, makeRow } from "../grid/columns/common";
import { timelineCollection } from "../grid/columns/timeline";
import { buildSelectionCsv } from "./csv";

const ZONES = ["utc", "Asia/Seoul", "America/New_York"] as const;

/** CSV data rows split into cells (no quoted commas in these fixtures). */
function csvCells(csv: string): { header: string[]; rows: string[][] } {
  const lines = csv
    .replace(/^\uFEFF/, "")
    .trimEnd()
    .split("\r\n");
  return { header: lines[0]?.split(",") ?? [], rows: lines.slice(1).map((line) => line.split(",")) };
}

afterEach(() => resetAppStore());

describe("D14 #8: undetermined-zone wall clock", () => {
  const wall = timelineCollection.mapRow(
    {
      timestamp: "2024-01-02T09:00:00",
      timezone: "local-unknown",
      event_type: "artifact-registry-network-profile-first-connected",
      timestamp_kind: "first-connected",
    },
    0,
    { ref: { id: "timeline" } },
  );
  const timeColumn = timelineCollection.columns[0];

  it("keeps the written 09:00 in every display zone of the CSV and grid", () => {
    for (const zone of ZONES) {
      resetAppStore({ timezone: zone });
      if (!timeColumn) throw new Error("timeline has no time column");
      const { header, rows } = csvCells(buildSelectionCsv([wall], [timeColumn], null));
      const cells = new Map(header.map((name, index) => [name, rows[0]?.[index] ?? ""]));
      expect(cells.get("시각")).toBe("2024-01-02 09:00:00 (현지 시각·시간대 미확정)");
      expect(cells.get("시각 UTC 원문")).toBe("");
      expect(cells.get("시간대 상태")).toBe("현지 시각(시간대 미확정·환산 안 함)");
      expect(timeColumn.format?.(wall)).toBe("2024-01-02 09:00:00 현지(미확정)");
      expect(timeColumn.tooltip?.(wall)).toContain("2024-01-02 09:00:00 (현지 시각·시간대 미확정)");
    }
  });

  it("puts an assumed conversion apart, with the assumed zone named", () => {
    expect(assumedUtcOfWallClock("2024-01-02 09:00:00", "Asia/Seoul")).toBe("2024-01-02T00:00:00Z");
    expect(assumedUtcOfWallClock("2024-01-02 09:00:00", null)).toBeNull();
    expect(assumedUtcOfWallClock("2024-01-02 09:00:00", "local")).toBeNull();
  });
});

describe("D14 #11: 100 ns ticks in the CSV and the FILETIME tooltip", () => {
  const stamps = ["2024-01-01T00:00:00.0000007Z", "2024-01-01T00:00:00.0000001Z"];
  const rows = stamps.map((timestamp, index) =>
    makeRow(
      makeRef("timeline", `/events/${index}`),
      { timestamp, title: `Event ${index}`, sourcePath: "events.evtx" },
      {},
    ),
  );

  it("CSV time cells and exact UTC keep the 1 and 7 tick digits in every zone", () => {
    for (const zone of ZONES) {
      resetAppStore({ timezone: zone });
      const { header, rows: lines } = csvCells(buildSelectionCsv(rows, [col.timestamp()], null));
      const at = (name: string) => header.indexOf(name);
      const [first, second] = lines;
      expect(first?.[at("시각")]).not.toBe(second?.[at("시각")]);
      expect(first?.[at("시각")]).toContain(".0000007");
      expect(second?.[at("시각")]).toContain(".0000001");
      expect([first?.[at("시각 UTC 원문")], second?.[at("시각 UTC 원문")]]).toEqual(stamps);
      expect([first?.[at("FILETIME")], second?.[at("FILETIME")]]).toEqual([
        "133485408000000007",
        "133485408000000001",
      ]);
      // Integer FILETIME order matches time order: #2 (…0001) before #1 (…0007).
      expect(BigInt(second?.[at("FILETIME")] ?? "0") < BigInt(first?.[at("FILETIME")] ?? "0")).toBe(true);
    }
  });

  it("an 18-digit JSON number is not shown as the FILETIME original", () => {
    // JSON.parse turns 133485408000000007 into 133485408000000000 (double rounding).
    const rounded = JSON.parse("133485408000000007") as number;
    const tooltip = evidenceTimeTooltip(stamps[0], "utc", rounded);
    expect(tooltip).toContain("FILETIME(환산) 133485408000000007");
    expect(tooltip).not.toContain("133485408000000000");
    expect(evidenceTimeTooltip(stamps[0], "utc", "133485408000000007")).toContain(
      "FILETIME 원문 133485408000000007",
    );
    expect(exactEvidenceTime(stamps[1], "Asia/Seoul")?.exactUtc).toBe(stamps[1]);
  });
});
