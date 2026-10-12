import { describe, expect, it } from "vitest";
import {
  collectionChanged,
  parseColumnFilters,
  parseHash,
  serializeColumnFilters,
  serializeRoute,
} from "./router";

// Plan analysis-workbench-p1 §4: `#/case/{run}/explore/analysis/{kind}?id=&row=&sort=&cols=&cf=`.
describe("analysis route", () => {
  it("parses node kind, job id, sort, cols and row", () => {
    const route = parseHash(
      "#/case/run-1/explore/analysis/carve?id=a1b2&row=analysis%7Ca1b2%7C%2Frows%2F7%7C%7C&sort=details.offset:desc&cols=details.notes",
    );
    expect(route).toMatchObject({
      runId: "run-1",
      collection: "analysis",
      kind: "carve",
      analysisId: "a1b2",
      sort: { key: "details.offset", order: "desc" },
      cols: ["details.notes"],
      row: { collection: "analysis", kind: "a1b2", locator: "/rows/7" },
    });
  });

  it("round-trips through serializeRoute", () => {
    const hash =
      "#/case/run-1/explore/analysis/vsc?id=j%2F1&row=analysis%7Cj%2F1%7C%2Frows%2F2%7C%7C&cf=d%3Ascore>3&sort=details.score:asc&cols=details.reason";
    const route = parseHash(hash);
    expect(route.analysisId).toBe("j/1");
    expect(serializeRoute(route)).toBe(hash);
    expect(parseHash(serializeRoute(route))).toEqual(route);
  });

  it("ignores id= outside the analysis collection and keeps the overview without a kind", () => {
    expect(parseHash("#/case/r/explore/files?id=x").analysisId).toBeUndefined();
    const overview = parseHash("#/case/r/explore/analysis");
    expect(overview).toEqual({ runId: "r", collection: "analysis" });
    expect(serializeRoute(overview)).toBe("#/case/r/explore/analysis");
  });

  it("a different job id is a different grid (selection resets)", () => {
    const a = parseHash("#/case/r/explore/analysis/carve?id=1");
    const b = parseHash("#/case/r/explore/analysis/carve?id=2");
    expect(collectionChanged(a, b)).toBe(true);
    expect(collectionChanged(a, parseHash("#/case/r/explore/analysis/carve?id=1&q=x"))).toBe(false);
  });
});

describe("cf= column filter grammar", () => {
  it("parses the plan example: contains, minimum, time range", () => {
    expect(parseColumnFilters("path:foo,size>1000,timestamp:2025-01-01..2025-02-01")).toEqual([
      { col: "path", op: ":", value: "foo" },
      { col: "size", op: ">", value: "1000" },
      { col: "timestamp", op: ":", value: "2025-01-01..2025-02-01" },
    ]);
  });

  it("reads browser-encoded < and > (%3C / %3E) as operators", () => {
    expect(parseColumnFilters("size%3E10,size%3c20")).toEqual([
      { col: "size", op: ">", value: "10" },
      { col: "size", op: "<", value: "20" },
    ]);
  });

  it("values carrying , : < > % and Korean survive a round trip; column ids with ':' too", () => {
    const filters = [
      { col: "path", op: ":" as const, value: "C:\\Users\\홍길동, a<b>%" },
      { col: "f:run_count", op: ">" as const, value: "5" },
      { col: "timestamp", op: ":" as const, value: "2025-01-01T00:00..2025-01-02" },
    ];
    const text = serializeColumnFilters(filters);
    expect(text.split(",")).toHaveLength(3); // no raw separator inside an entry
    expect(parseColumnFilters(text)).toEqual(filters);
    const route = parseHash(`#/case/r/explore/files?cf=${text}`);
    expect(route.cf).toEqual(filters);
    expect(parseHash(serializeRoute(route)).cf).toEqual(filters);
  });

  it("drops malformed entries (no operator, empty column or value) and empty filters from the URL", () => {
    expect(parseColumnFilters("nooperator,:x,size>,path:ok")).toEqual([
      { col: "path", op: ":", value: "ok" },
    ]);
    expect(serializeColumnFilters([{ col: "path", op: ":", value: "  " }])).toBe("");
    expect(serializeRoute({ runId: "r", collection: "files", cf: [] })).toBe("#/case/r/explore/files");
  });
});
