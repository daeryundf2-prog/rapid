import { describe, expect, it } from "vitest";
import type { ColumnFilter, GridRow } from "../../contracts/collection";
import { col, makeRef, makeRow } from "../grid/columns/common";
import type { ColumnSpec } from "../grid/types";
import {
  applyColumnFilters,
  filterKindOf,
  joinTimeRange,
  matchesColumnFilter,
  setColumnFilter,
  splitTimeRange,
  timeBounds,
} from "./columnFilters";
import {
  applyFiltersToQuery,
  clientOnlyFilters,
  EMPTY_FILTERS,
  type FilterState,
  partitionFilters,
} from "./filterModel";

const f = (columns: ColumnFilter[], over: Partial<FilterState> = {}): FilterState => ({
  ...EMPTY_FILTERS,
  ...over,
  columns,
});

function row(i: number, size: number, at: string, path: string): GridRow {
  return makeRow(
    makeRef("files", `/candidates/${i}`),
    { title: `file-${i}`, sourcePath: path, timestamp: at },
    { size },
  );
}

const sizeCol: ColumnSpec = col.field("size", "크기", 90, ["analysis"], (r) => r.fields.size as number, {
  align: "right",
});
const columns = new Map<string, ColumnSpec>([
  ["size", sizeCol],
  ["timestamp", col.timestamp()],
  ["path", col.path()],
  ["title", col.title("이름")],
]);
const resolve = (id: string) => columns.get(id);
const rows = [
  row(0, 10, "2025-01-01T10:00:00Z", "C:/a/One.txt"),
  row(1, 2000, "2025-01-15T00:00:00Z", "C:/b/two.txt"),
  row(2, 5000, "2025-02-03T00:00:00Z", "C:/a/three.TXT"),
];

describe("column filter predicates (plan analysis-workbench-p1 U-P1-4)", () => {
  it("infers the input kind: timestamp → time, right-aligned → number, else text", () => {
    expect(filterKindOf(col.timestamp())).toBe("time");
    expect(filterKindOf(sizeCol)).toBe("number");
    expect(filterKindOf(col.path())).toBe("text");
    expect(filterKindOf({ ...col.path(), filterKind: "none" })).toBe("none");
  });

  it("text = case-insensitive contains; number = inclusive min/max; time = [from, to] with whole-day 'to'", () => {
    const keep = (filters: ColumnFilter[]) => applyColumnFilters(rows, filters, resolve).map((r) => r.title);
    expect(keep([{ col: "path", op: ":", value: "/A/" }])).toEqual(["file-0", "file-2"]);
    expect(keep([{ col: "size", op: ">", value: "2000" }])).toEqual(["file-1", "file-2"]);
    expect(
      keep([
        { col: "size", op: ">", value: "100" },
        { col: "size", op: "<", value: "2000" },
      ]),
    ).toEqual(["file-1"]);
    expect(keep([{ col: "timestamp", op: ":", value: "2025-01-01..2025-01-15" }])).toEqual([
      "file-0",
      "file-1",
    ]);
    expect(keep([{ col: "timestamp", op: ":", value: "2025-02-01.." }])).toEqual(["file-2"]);
    // Unknown columns are ignored rather than hiding every row.
    expect(keep([{ col: "nope", op: ":", value: "x" }])).toHaveLength(3);
  });

  it("a malformed bound never hides rows (the input marks it invalid instead)", () => {
    expect(matchesColumnFilter(sizeCol, rows[0] as GridRow, { col: "size", op: ">", value: "abc" })).toBe(
      true,
    );
    expect(timeBounds("not-a-date..").valid).toBe(false);
  });

  it("editing helpers replace one operator of one column and split/join time ranges", () => {
    let list = setColumnFilter([], "size", ">", "10");
    list = setColumnFilter(list, "size", "<", "20");
    list = setColumnFilter(list, "size", ">", "15");
    expect(list).toEqual([
      { col: "size", op: "<", value: "20" },
      { col: "size", op: ">", value: "15" },
    ]);
    expect(setColumnFilter(list, "size", "<", " ")).toEqual([{ col: "size", op: ">", value: "15" }]);
    expect(joinTimeRange("2025-01-01", "")).toBe("2025-01-01..");
    expect(joinTimeRange("", "")).toBe("");
    expect(splitTimeRange("..2025-02-01")).toEqual(["", "2025-02-01"]);
  });
});

describe("column filters: server vs client partition (plan §4)", () => {
  it("artifacts: 경로 → path_contains, 유형 → artifact_type; other columns stay client-side", () => {
    const filters = f([
      { col: "path", op: ":", value: "Users" },
      { col: "type", op: ":", value: "web-server-log" },
      { col: "d:source_size", op: ">", value: "1000" },
    ]);
    const plan = partitionFilters({ id: "artifacts", kind: "windows-system" }, filters);
    expect(plan.server).toEqual({ path: "Users", artifactTypes: ["web-server-log"] });
    expect(plan.serverColumns.map((c) => c.col)).toEqual(["path", "type"]);
    expect(plan.clientColumns).toEqual([{ col: "d:source_size", op: ">", value: "1000" }]);
    expect(plan.serverLabels).toEqual(["유형(정확히)", "열 필터"]);
    expect(plan.clientLabels).toEqual(["열 필터"]);
    const query = applyFiltersToQuery(
      { ref: { id: "artifacts", kind: "windows-system" }, offset: 0, limit: 250 },
      filters,
    );
    expect(query.pathContains).toBe("Users");
    expect(query.artifactTypes).toEqual(["web-server-log"]);
    expect(clientOnlyFilters(filters, plan).columns).toEqual(plan.clientColumns);
  });

  it("analysis rows: 경로 → path_contains; search: 확장자 → extension", () => {
    const analysis = partitionFilters(
      { id: "analysis", kind: "carve", analysisId: "a1" },
      f([{ col: "path", op: ":", value: "dump" }]),
    );
    expect(analysis.server.path).toBe("dump");
    expect(analysis.clientColumns).toEqual([]);
    const search = partitionFilters({ id: "search" }, f([{ col: "extension", op: ":", value: ".DOCX" }]));
    expect(search.server.extension).toEqual(["docx"]);
  });

  it("files: every column filter (even 경로) is client-side over loaded rows", () => {
    const plan = partitionFilters(
      { id: "files" },
      f([
        { col: "path", op: ":", value: "Users" },
        { col: "size", op: ">", value: "1000" },
      ]),
    );
    expect(plan.server).toEqual({});
    expect(plan.clientColumns).toHaveLength(2);
    expect(plan.clientLabels).toEqual(["열 필터"]);
  });

  it("the filter-bar path wins path_contains; a 경로 column filter then stays client-side", () => {
    const plan = partitionFilters(
      { id: "artifacts" },
      f([{ col: "path", op: ":", value: "b" }], { path: "a" }),
    );
    expect(plan.server.path).toBe("a");
    expect(plan.clientColumns).toEqual([{ col: "path", op: ":", value: "b" }]);
  });
});

describe("메모 있음 filter (검토 panel)", () => {
  it("keeps only rows with a note, client-side, and round-trips note=1", async () => {
    const { rowMatchesFilters, filtersFromRoute, filtersToRoutePatch } = await import("./filterModel");
    const { parseHash, serializeRoute } = await import("../../router");
    const withNote = makeRow(
      makeRef("review", "case-db:file_record:1"),
      { title: "a" },
      { note: "확인 필요" },
    );
    const without = makeRow(makeRef("review", "case-db:file_record:2"), { title: "b" }, {});
    const filters = { ...EMPTY_FILTERS, notes: true };
    expect(rowMatchesFilters(withNote, filters)).toBe(true);
    expect(rowMatchesFilters(without, filters)).toBe(false);
    expect(partitionFilters({ id: "review" }, filters).clientLabels).toEqual(["메모 있음"]);
    const route = parseHash("#/case/r/review/board?note=1");
    expect(filtersFromRoute(route).notes).toBe(true);
    expect(serializeRoute({ ...route, ...filtersToRoutePatch({ ...EMPTY_FILTERS }) })).toBe(
      "#/case/r/review/board",
    );
  });
});
