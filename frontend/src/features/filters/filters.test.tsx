import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { parseHash, serializeRoute } from "../../router";
import { useAppStore } from "../../state/store";
import { COLLECTIONS, presetColumnIds } from "../grid/columns";
import { setAxiomMode } from "../grid/columns/axiom";
import { makeRef, makeRow } from "../grid/columns/common";
import { displayText } from "../grid/gridUtils";
import { FilterBar } from "./FilterBar";
import {
  activeChips,
  applyClientFilters,
  applyFiltersToQuery,
  EMPTY_FILTERS,
  type FilterState,
  filtersFromRoute,
  filtersToRoutePatch,
  partitionFilters,
  removeChip,
} from "./filterModel";
import { FILTER_EVENT, setTimeRange, useFilterStore } from "./filterStore";

function row(over: Partial<GridRow> & { title: string }, fields: Record<string, unknown> = {}): GridRow {
  return makeRow(makeRef("files", `/candidates/${over.title}`), over, fields);
}

const HASH = "#/case/r1/files";

beforeEach(() => {
  window.location.hash = HASH;
  useAppStore.setState({ route: parseHash(HASH) });
  useFilterStore.setState({ filters: EMPTY_FILTERS, report: null });
});
afterEach(() => {
  window.location.hash = "";
});

describe("URL round trip", () => {
  it("serialises and parses every filter param", () => {
    const hash = serializeRoute({
      runId: "r1",
      collection: "files",
      q: "a b",
      from: "2026-01-01T00:00",
      to: "2026-01-02T00:00",
      statuses: ["relevant", "needs-review"],
      types: ["eventlog", "a,b"],
      ext: ["docx"],
      path: "C:/Users",
    });
    expect(hash).toContain("status=relevant,needs-review");
    const back = parseHash(hash);
    expect(back.types).toEqual(["eventlog", "a,b"]);
    expect(back.statuses).toEqual(["relevant", "needs-review"]);
    expect(back.path).toBe("C:/Users");
    expect(filtersToRoutePatch(filtersFromRoute(back)).from).toBe("2026-01-01T00:00");
  });

  it("store writes the route and follows it", () => {
    act(() => useFilterStore.getState().patchFilters({ types: ["evtx"], ext: [".DOCX"] }));
    expect(useAppStore.getState().route.types).toEqual(["evtx"]);
    expect(useAppStore.getState().route.ext).toEqual(["docx"]);
    expect(window.location.hash).toContain("types=evtx");
    act(() => useAppStore.getState().patchRoute({ types: undefined, ext: undefined }, { replace: true }));
    expect(useFilterStore.getState().filters.types).toEqual([]);
  });
});

describe("histogram event and setTimeRange", () => {
  it("rapidtriage:filter sets and clears the range", () => {
    window.dispatchEvent(
      new CustomEvent(FILTER_EVENT, { detail: { from: "2026-02-01T00:00:00Z", to: "2026-02-02T00:00:00Z" } }),
    );
    expect(useFilterStore.getState().filters.from).toBe("2026-02-01T00:00:00Z");
    expect(useAppStore.getState().route.to).toBe("2026-02-02T00:00:00Z");
    window.dispatchEvent(new CustomEvent(FILTER_EVENT, { detail: {} }));
    expect(useFilterStore.getState().filters.from).toBeUndefined();
    setTimeRange("2026-03-01T00:00", "2026-03-02T00:00");
    expect(useFilterStore.getState().filters.to).toBe("2026-03-02T00:00");
  });
});

describe("server vs client partition", () => {
  const f = (over: Partial<FilterState>): FilterState => ({ ...EMPTY_FILTERS, ...over });

  it("artifacts: path and types go to the API (artifact_type=, plan analysis-workbench-p1 U-P1-5)", () => {
    const plan = partitionFilters(
      { id: "artifacts" },
      f({ path: "Users", types: ["web-server-log", "webshell-source-candidate"], tags: ["x"] }),
    );
    expect(plan.server).toEqual({
      path: "Users",
      artifactTypes: ["web-server-log", "webshell-source-candidate"],
    });
    expect(plan.serverLabels).toEqual(["유형", "경로"]);
    expect(plan.clientLabels).toEqual(["태그"]);
    const q = applyFiltersToQuery(
      { ref: { id: "artifacts", kind: "windows-system" }, offset: 0, limit: 250 },
      f({ path: "Users", types: ["web-server-log"] }),
    );
    expect(q.pathContains).toBe("Users");
    expect(q.artifactTypes).toEqual(["web-server-log"]);
    // The kind stays the routed one: a type is not a kind.
    expect(q.ref.kind).toBe("windows-system");
  });

  it("search: extension is server-side; timeline: time range is client-side", () => {
    expect(partitionFilters({ id: "search" }, f({ ext: ["pdf"] })).server.extension).toEqual(["pdf"]);
    const t = partitionFilters({ id: "timeline" }, f({ from: "2026-01-01T00:00", ext: ["pdf"] }));
    expect(t.serverLabels).toEqual([]);
    expect(t.clientLabels).toEqual(["시간 범위", "확장자"]);
  });

  it("client predicate filters time, status, type, tag, ext and path", () => {
    const rows = [
      row({
        title: "a.docx",
        timestamp: "2026-01-05T00:00:00Z",
        reviewStatus: "relevant",
        artifactType: "doc",
        tags: ["t1"],
        sourcePath: "C:/Users/a.docx",
      }),
      row({
        title: "b.pdf",
        timestamp: "2026-03-05T00:00:00Z",
        reviewStatus: "excluded",
        artifactType: "pdf",
        tags: [],
        sourcePath: "D:/b.pdf",
      }),
      row({ title: "c", timestamp: null }),
    ];
    const out = (s: Partial<FilterState>) => applyClientFilters(rows, f(s)).map((r) => r.title);
    expect(out({ from: "2026-01-01T00:00:00Z", to: "2026-02-01T00:00:00Z" })).toEqual(["a.docx"]);
    expect(out({ statuses: ["excluded"] })).toEqual(["b.pdf"]);
    expect(out({ types: ["DOC"] })).toEqual(["a.docx"]);
    expect(out({ tags: ["t1"] })).toEqual(["a.docx"]);
    expect(out({ ext: ["pdf"] })).toEqual(["b.pdf"]);
    expect(out({ path: "users" })).toEqual(["a.docx"]);
    expect(out({})).toHaveLength(3);
  });
});

describe("chips", () => {
  it("lists active filters and removes one at a time", () => {
    const filters: FilterState = {
      ...EMPTY_FILTERS,
      statuses: ["relevant"],
      ext: ["pdf", "docx"],
      path: "x",
    };
    const chips = activeChips(filters, (s) => s);
    expect(chips.map((c) => c.label)).toEqual(["상태 relevant", "확장자 .pdf", "확장자 .docx", "경로 x"]);
    const next = removeChip(filters, chips[1] as (typeof chips)[number]);
    expect(next.ext).toEqual(["docx"]);
  });

  it("FilterBar adds a status chip, removes it, and resets", () => {
    render(<FilterBar filterRef={{ current: null }} query="" onQuery={() => {}} onReturnToGrid={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "상태 필터: 재검토" }));
    expect(useFilterStore.getState().filters.statuses).toEqual(["needs-review"]);
    fireEvent.click(screen.getByRole("button", { name: /상태 재검토 필터 제거/ }));
    expect(useFilterStore.getState().filters.statuses).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "7일" }));
    expect(useFilterStore.getState().filters.from).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "필터 초기화" }));
    expect(useFilterStore.getState().filters.from).toBeUndefined();
  });
});

describe("AXIOM preset columns", () => {
  afterEach(() => setAxiomMode(false));

  it("puts title first, a tag/status column second, and renders two lines", () => {
    const cols = COLLECTIONS.timeline.columns;
    expect(cols[0]?.id).toBe("title");
    expect(cols[1]?.id).toBe("tagstatus");
    expect(presetColumnIds(cols, "axiom")).toEqual(["title", "tagstatus", "timestamp", "path"]);
    const r = row({ title: "로그온", artifactType: "evtx", reviewStatus: "relevant", tags: ["증거"] });
    const spec = cols[0];
    expect(spec && displayText(spec, r)).toBe("로그온");
    setAxiomMode(true);
    expect(spec && displayText(spec, r)).toBe("로그온\nevtx");
    expect(cols[1] && displayText(cols[1], r)).toBe("● 관련 있음 · #증거");
  });
});
