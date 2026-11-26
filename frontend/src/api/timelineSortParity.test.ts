import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { GridRow } from "../contracts/collection";
import { timelineCollection } from "../features/grid/columns/timeline";

/**
 * `GET /timeline?sort=timestamp` (rapidtriage/api/app/evidence_sort.py) must order the events
 * exactly as the grid's own sort of the 시각 column did before the timeline was server-sorted:
 * the column comparator, reversed for desc, ties in record order (@tanstack/table-core
 * createSortedRowModel). The fixture is shared with tests/test_console_api_review.py.
 */
interface Parity {
  events: unknown[];
  asc: number[];
  desc: number[];
}

const fixture = JSON.parse(
  readFileSync(join(process.cwd(), "..", "tests", "fixtures", "timeline-sort-parity.json"), "utf8"),
) as Parity;

function clientOrder(desc: boolean): number[] {
  const spec = timelineCollection.columns.find((column) => column.id === "timestamp");
  if (!spec?.compare) throw new Error("the timeline 시각 column has no comparator");
  const compare = spec.compare;
  const rows: GridRow[] = fixture.events.map((raw, position) =>
    timelineCollection.mapRow(raw as Record<string, unknown>, position, { ref: { id: "timeline" } }),
  );
  return rows
    .map((row, index) => ({ row, index }))
    .sort((a, b) => {
      const order = compare(a.row, b.row);
      if (order !== 0) return desc ? -order : order;
      return a.index - b.index;
    })
    .map((item) => item.index);
}

describe("timeline sort parity with the server", () => {
  it("orders ascending like the server", () => {
    expect(clientOrder(false)).toEqual(fixture.asc);
  });

  it("orders descending like the server", () => {
    expect(clientOrder(true)).toEqual(fixture.desc);
  });
});
