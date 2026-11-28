import { describe, expect, it } from "vitest";
import { matchesColumnFilter } from "../../filters/columnFilters";
import type { ColumnSpec } from "../types";
import { reviewCollection } from "./review";

// review #101 P3-1: 접수's "관련 있음 · 보고서 미포함" link opens the board with cf=report:미포함;
// the 보고서 column has to spell 미포함 out, or the link always lands on an empty list.
describe("review board 보고서 column", () => {
  const row = (includeInReport: boolean) =>
    reviewCollection.mapRow(
      {
        _store: "case-db",
        status: "relevant",
        target_type: "run_output",
        target_id: "1",
        include_in_report: includeInReport,
      },
      0,
      { ref: { id: "review" } } as never,
    );
  const report = reviewCollection.columns.find((column) => column.id === "report") as ColumnSpec;
  const filter = { col: "report", op: ":", value: "미포함" } as const;

  it("reads 포함 / 미포함 and the 미포함 filter keeps only rows left out of the report", () => {
    expect(report.value(row(true))).toBe("포함");
    expect(report.value(row(false))).toBe("미포함");
    expect(matchesColumnFilter(report, row(false), filter)).toBe(true);
    expect(matchesColumnFilter(report, row(true), filter)).toBe(false);
  });
});
