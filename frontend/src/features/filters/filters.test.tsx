import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
  cleanup();
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
    fireEvent.click(screen.getByRole("button", { name: /^필터/ }));
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

describe("one-line filter bar (visual-polish S1/S2)", () => {
  const bar = (props: Partial<Parameters<typeof FilterBar>[0]> = {}) =>
    render(
      <FilterBar
        filterRef={{ current: null }}
        query=""
        onQuery={() => {}}
        onReturnToGrid={() => {}}
        {...props}
      />,
    );

  it("keeps every condition in the 필터 popover; applied ones show as chips on the one line", () => {
    bar();
    const search = document.querySelector("search.filter-bar") as HTMLElement;
    // One line: search + 필터 button, no time inputs until the popover opens.
    expect(within(search).queryByLabelText("시작 시각")).toBeNull();
    const trigger = screen.getByRole("button", { name: /^필터/ });
    expect(trigger.getAttribute("aria-haspopup")).toBe("dialog");
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(trigger);
    const popover = screen.getByRole("dialog", { name: "필터 조건" });
    expect(trigger.getAttribute("aria-expanded")).toBe("true");
    expect(trigger.getAttribute("aria-controls")).toBe(popover.id);
    for (const group of ["시간 범위", "아티팩트 유형", "태그·상태"])
      expect(within(popover).getByRole("group", { name: group })).toBeTruthy();
    expect(within(popover).getByLabelText("시작 시각")).toBeTruthy();
    expect(within(popover).getByLabelText("종료 시각")).toBeTruthy();
    for (const field of ["태그", "확장자", "경로 포함"])
      expect(within(popover).getByLabelText(field)).toBeTruthy();
    fireEvent.click(within(popover).getByRole("button", { name: "상태 필터: 제외" }));
    fireEvent.click(within(popover).getByRole("button", { name: "30일" }));
    // The trigger counts the applied conditions; each is a removable chip.
    expect(trigger.textContent).toContain("2");
    const chips = screen.getByRole("list", { name: "적용된 필터" });
    expect(within(chips).getAllByRole("listitem")).toHaveLength(2);
  });

  it("popover keyboard: opening focuses the heading (not 오늘), Tab cycles inside, Esc closes and returns focus", () => {
    bar();
    const trigger = screen.getByRole("button", { name: /^필터/ });
    trigger.focus();
    fireEvent.click(trigger);
    const popover = screen.getByRole("dialog", { name: "필터 조건" });
    // Review #10: focus lands on the popover heading so the first preset is not pre-armed.
    expect(document.activeElement).toBe(within(popover).getByRole("heading", { name: "필터 조건" }));
    const first = within(popover).getByRole("button", { name: "오늘" });
    const close = within(popover).getByRole("button", { name: /^적용/ });
    close.focus();
    fireEvent.keyDown(close, { key: "Tab" });
    expect(document.activeElement).toBe(first);
    fireEvent.keyDown(first, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(close);
    fireEvent.keyDown(close, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "필터 조건" })).toBeNull();
    expect(document.activeElement).toBe(trigger);
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
  });

  it("a pointer press outside closes the popover without moving focus", () => {
    bar();
    fireEvent.click(screen.getByRole("button", { name: /^필터/ }));
    expect(screen.getByRole("dialog", { name: "필터 조건" })).toBeTruthy();
    fireEvent.pointerDown(document.body);
    expect(screen.queryByRole("dialog", { name: "필터 조건" })).toBeNull();
  });

  it("검토 toolbar: review status + tag + search, no time range or 필터 popover", () => {
    const onReviewStatus = vi.fn();
    bar({ variant: "review", reviewStatus: "relevant", onReviewStatus });
    expect(screen.queryByRole("button", { name: /^필터/ })).toBeNull();
    expect(screen.queryByLabelText("시작 시각")).toBeNull();
    const status = screen.getByRole("combobox", { name: "리뷰 상태" }) as HTMLSelectElement;
    expect(status.value).toBe("relevant");
    fireEvent.change(status, { target: { value: "excluded" } });
    expect(onReviewStatus).toHaveBeenCalledWith("excluded");
    fireEvent.change(status, { target: { value: "" } });
    expect(onReviewStatus).toHaveBeenLastCalledWith(undefined);
    const tag = screen.getByLabelText("태그");
    fireEvent.change(tag, { target: { value: "악성" } });
    fireEvent.keyDown(tag, { key: "Enter" });
    expect(useFilterStore.getState().filters.tags).toEqual(["악성"]);
    expect(screen.getByRole("button", { name: "태그 악성 필터 제거" })).toBeTruthy();
  });

  it("보고 toolbar: export kind + search; the kind is the type filter, shown as 종류", () => {
    bar({ variant: "report", kindOptions: ["보고서", "아티팩트"] });
    expect(screen.queryByRole("button", { name: /^필터/ })).toBeNull();
    expect(screen.queryByRole("combobox", { name: "리뷰 상태" })).toBeNull();
    const kind = screen.getByRole("combobox", { name: "종류" }) as HTMLSelectElement;
    expect(Array.from(kind.options).map((o) => o.textContent)).toEqual(["전체", "보고서", "아티팩트"]);
    fireEvent.change(kind, { target: { value: "아티팩트" } });
    expect(useFilterStore.getState().filters.types).toEqual(["아티팩트"]);
    expect(useAppStore.getState().route.types).toEqual(["아티팩트"]);
    expect(screen.getByRole("button", { name: "종류 아티팩트 필터 제거" })).toBeTruthy();
    fireEvent.change(kind, { target: { value: "" } });
    expect(useFilterStore.getState().filters.types).toEqual([]);
  });

  it("outputs carry their kind so the 종류 filter applies to the loaded rows", () => {
    const rows = [
      "artifacts_browser",
      "report",
      "files",
      "docs_extract_manifest",
      "case_db",
      "fingerprint",
    ].map((name, index) =>
      COLLECTIONS.outputs.mapRow({ name, path: `C:/o/${name}.json` }, index, { ref: { id: "outputs" } }),
    );
    expect(rows.map((r) => r.artifactType)).toEqual([
      "아티팩트",
      "보고서",
      "목록·색인",
      "추출",
      "케이스 DB",
      "처리 기록",
    ]);
    const kept = applyClientFilters(rows, { ...EMPTY_FILTERS, types: ["보고서"] }).map((r) => r.title);
    expect(kept).toEqual(["report"]);
  });
});

describe("AXIOM preset columns", () => {
  afterEach(() => setAxiomMode(false));

  it("adds the tag/status column right after the title (kept in place) and renders two lines", () => {
    // The title keeps its place in the collection order (visual-polish S4: 시각 leads the timeline);
    // the AXIOM preset moves chip + title to the front in the grid (DataGrid orderedColumns).
    const cols = COLLECTIONS.timeline.columns;
    const at = cols.findIndex((c) => c.id === "title");
    expect(cols[at + 1]?.id).toBe("tagstatus");
    expect(new Set(presetColumnIds(cols, "axiom"))).toEqual(
      new Set(["title", "tagstatus", "timestamp", "path"]),
    );
    const r = row({ title: "로그온", artifactType: "evtx", reviewStatus: "relevant", tags: ["증거"] });
    const spec = cols[at];
    expect(spec && displayText(spec, r)).toBe("로그온");
    setAxiomMode(true);
    expect(spec && displayText(spec, r)).toBe("로그온\nevtx");
    expect(cols[at + 1] && displayText(cols[at + 1] as (typeof cols)[number], r)).toBe("● 관련 있음 · #증거");
  });
});
