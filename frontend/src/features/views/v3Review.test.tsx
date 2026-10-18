// biome-ignore-all lint/a11y: tests drive ARIA widgets through their DOM roles
/**
 * r4 V3 adversarial review fixes: time ranges in order / whole last minute (F1), hour pickers
 * (F2), modifier keys (F3), card list focus by row key (F4), URL / saved-set validation (F5, F8),
 * half-open geo boxes (F6), Korean error text (F7), map empty / scanning states (F9), 부분 결과 /
 * 콘텐츠 유형 rules mirrored from the server, server-filtered counts.
 */
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchFilesPage, fetchTimelinePage } from "../../api/collections";
import { resetCommandRegistry } from "../../commands/registry";
import type { GridRow } from "../../contracts/collection";
import { parseHash } from "../../router";
import { resetAppStore, useAppStore } from "../../state/store";
import { DerivedGraph } from "../derived/DerivedGraph";
import type { DerivedGraph as Graph } from "../derived/graph";
import { ClockSection } from "../filters/ConditionSections";
import { normalizeFilters } from "../filters/conditionMemory";
import { inGeoBox, normalizeHours, parseGeo } from "../filters/conditionValues";
import { rowContentTypes } from "../filters/contentTypes";
import { EMPTY_FILTERS, type FilterState, rowMatchesFilters } from "../filters/filterModel";
import { useFilterStore } from "../filters/filterStore";
import {
  boundUnitMs,
  hoursAfterPick,
  orderedRange,
  rowIsPartial,
  serverConditionParams,
  timeWindow,
} from "../filters/rowConditions";
import { useGridLocalStore } from "../grid/adapter";
import {
  filesHandler,
  installFetch,
  jsonResponse,
  mockLayout,
  queryWrapper,
  resetGridStore,
} from "../grid/testSupport";
import { CARD_HEIGHT, CardView, isPlainKey, resolveActiveIndex } from "./CardView";
import { clusterRows } from "./geo";
import { MapView } from "./MapView";

const f = (patch: Partial<FilterState>): FilterState => ({ ...EMPTY_FILTERS, ...patch });

function row(partial: Partial<GridRow> & { rowKey: string }): GridRow {
  return {
    ref: { collection: "artifacts", locator: partial.rowKey },
    title: partial.rowKey,
    sourcePath: null,
    timestamp: null,
    artifactType: null,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: {},
    ...partial,
  };
}

let restoreLayout: () => void = () => {};

beforeEach(() => {
  resetCommandRegistry();
  resetAppStore();
  resetGridStore();
  restoreLayout = mockLayout(800, 600);
});

afterEach(() => {
  cleanup();
  restoreLayout();
  vi.unstubAllGlobals();
});

describe("F1 time range: in order, the last minute included", () => {
  it("never sends a reversed range and sends minute inputs at minute precision", () => {
    const params = serverConditionParams(
      f({ from: "2025-05-30T12:00:00Z", to: "2025-05-30T09:00:00Z" }),
      "utc",
      { time: true, geo: false },
    );
    expect(params.from).toBe("2025-05-30T09:00:00.000Z");
    expect(params.to).toBe("2025-05-30T12:00:00Z"); // second precision kept: the server includes that second
    expect(orderedRange("2025-05-30T12:00", "2025-05-30T09:00").reversed).toBe(true);
    const minute = serverConditionParams(f({ to: "2025-05-30T09:00" }), "utc", { time: true, geo: false });
    // `…T09:00` (local) goes as a minute-precision UTC instant: the server keeps the whole minute.
    expect(String(minute.to)).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z$/);
    expect(Date.parse(String(minute.to))).toBe(Date.parse("2025-05-30T09:00"));
  });

  it("checks loaded rows against [from, end of the named minute)", () => {
    expect(boundUnitMs("2025-05-30T09:00")).toBe(60_000);
    expect(boundUnitMs("2025-05-30T09:00:30")).toBe(1_000);
    expect(boundUnitMs("2025-05-30")).toBe(86_400_000);
    expect(boundUnitMs("2025-05-30T09:00:30.500Z")).toBe(1);
    const window = timeWindow("2025-05-30T10:00:00Z", "2025-05-30T09:00:00Z");
    expect(window).toEqual({
      from: Date.parse("2025-05-30T09:00:00Z"),
      until: Date.parse("2025-05-30T10:00:00Z") + 1_000,
    });
    const inside = row({ rowKey: "a", timestamp: "2025-05-30T09:30:00Z" });
    // Reversed bounds still select the rows between them.
    expect(rowMatchesFilters(inside, f({ from: "2025-05-30T10:00:00Z", to: "2025-05-30T09:00:00Z" }))).toBe(
      true,
    );
    // 최근 n일 ends at the current minute: a row 30 s into that minute is kept.
    const to = "2025-05-30T09:00";
    const late = row({ rowKey: "b", timestamp: new Date(Date.parse(to) + 30_000).toISOString() });
    expect(rowMatchesFilters(late, f({ to }))).toBe(true);
    const next = row({ rowKey: "c", timestamp: new Date(Date.parse(to) + 60_000).toISOString() });
    expect(rowMatchesFilters(next, f({ to }))).toBe(false);
  });
});

describe("F2 hour pickers", () => {
  it("moves the other bound instead of clearing the window", () => {
    expect(hoursAfterPick([9, 18], "start", 18)).toBe("18-19");
    expect(hoursAfterPick([18, 19], "end", 9)).toBe("18-09");
    expect(hoursAfterPick([18, 9], "end", 18)).toBe("17-18");
    expect(hoursAfterPick([0, 1], "end", 0)).toBe("23-00");
  });

  it("reaches 18–09 from the default window through the dropdowns", () => {
    useAppStore.getState().patchRoute({ runId: "r", collection: "artifacts" });
    render(<ClockSection />);
    fireEvent.change(screen.getByRole("combobox", { name: "시작 시" }), { target: { value: "18" } });
    expect(useFilterStore.getState().filters.hours).toBe("18-19");
    fireEvent.change(screen.getByRole("combobox", { name: /끝 시/ }), { target: { value: "9" } });
    expect(useFilterStore.getState().filters.hours).toBe("18-09");
    fireEvent.change(screen.getByRole("combobox", { name: /끝 시/ }), { target: { value: "18" } });
    expect(useFilterStore.getState().filters.hours).toBe("17-18");
  });
});

describe("F5 / F8 URL and saved-set validation", () => {
  it("drops unknown content / weekday ids, empty hour windows and bad boxes", () => {
    const route = parseHash(
      "#/case/r/explore/artifacts/media-image?wd=mon,funday,mon&hours=9-9&content=image,movie&geo=91,0,95,1",
    );
    expect(route.weekdays).toEqual(["mon"]);
    expect(route.hours).toBeUndefined();
    expect(route.content).toEqual(["image"]);
    expect(route.geo).toBeUndefined();
    expect(parseHash("#/case/r/explore/artifacts?hours=25-03").hours).toBeUndefined();
    expect(parseHash("#/case/r/explore/artifacts?hours=9-18").hours).toBe("09-18");
    expect(parseHash("#/case/r/explore/artifacts/media-image?geo=37.48,126.94,37.49,126.95").geo).toBe(
      "37.48,126.94,37.49,126.95",
    );
    // geo belongs to artifact listings only.
    expect(parseHash("#/case/r/explore/files?geo=37.48,126.94,37.49,126.95").geo).toBeUndefined();
    const saved = normalizeFilters({
      weekdays: ["sun", "x", "mon"],
      hours: "7-7",
      content: ["mail", "movie"],
      geo: "10,0,5,1",
    });
    expect(saved.weekdays).toEqual(["mon", "sun"]);
    expect(saved.hours).toBeUndefined();
    expect(saved.content).toEqual(["mail"]);
    expect(saved.geo).toBeUndefined();
    expect(normalizeHours("24-6")).toBe("00-06");
  });
});

describe("F6 geo boxes", () => {
  it("are half-open, include the world edge and cross the antimeridian", () => {
    expect(parseGeo("10,0,10,1")).toBeNull();
    expect(parseGeo("0,5,1,5")).toBeNull();
    expect(parseGeo(",1,2,3")).toBeNull();
    expect(parseGeo("-10,170,10,-170")).toEqual([-10, 170, 10, -170]);
    expect(inGeoBox({ lat: 10, lon: 10 }, [10, 10, 20, 20])).toBe(true);
    expect(inGeoBox({ lat: 20, lon: 15 }, [10, 10, 20, 20])).toBe(false);
    expect(inGeoBox({ lat: 90, lon: 180 }, [89.99, 179.99, 90, 180])).toBe(true);
    expect(inGeoBox({ lat: 0, lon: -175 }, [-10, 170, 10, -170])).toBe(true);
    expect(inGeoBox({ lat: 0, lon: 0 }, [-10, 170, 10, -170])).toBe(false);
    const edge = row({ rowKey: "e", fields: { details: { gps_latitude: 37.49, gps_longitude: 126.95 } } });
    expect(rowMatchesFilters(edge, f({ geo: "37.48,126.94,37.49,126.95" }))).toBe(false);
    expect(rowMatchesFilters(edge, f({ geo: "37.49,126.95,37.5,126.96" }))).toBe(true);
  });

  it("keeps cluster boxes inside ±90 / ±180 (the server accepts every one)", () => {
    const clusters = clusterRows([
      { row: row({ rowKey: "n" }), lat: 90, lon: 180, time: null },
      { row: row({ rowKey: "s" }), lat: -90, lon: -180, time: null },
    ]);
    for (const cluster of clusters) {
      const box = parseGeo(cluster.box);
      expect(box).not.toBeNull();
      expect(
        inGeoBox(
          {
            lat: cluster.rows[0]?.rowKey === "n" ? 90 : -90,
            lon: cluster.rows[0]?.rowKey === "n" ? 180 : -180,
          },
          box as never,
        ),
      ).toBe(true);
    }
    expect(clusters.map((cluster) => cluster.box).sort()).toEqual([
      "-90,-180,-89.99,-179.99",
      "89.99,179.99,90,180",
    ]);
  });
});

describe("부분 결과 / 콘텐츠 유형 follow the server rules", () => {
  it("separates display caps from read caps and reads statuses by whole words", () => {
    const partial = (details: Record<string, unknown>) =>
      rowIsPartial(row({ rowKey: "p", fields: { details } }));
    expect(partial({ message_text_truncated: true })).toBe(false);
    expect(partial({ event_data_truncated: true })).toBe(false);
    expect(partial({ scan_truncated: true })).toBe(true);
    expect(partial({ parse_status: "parsed-no-errors" })).toBe(false);
    expect(partial({ parse_status: "header-unrecognized" })).toBe(true);
    expect(partial({ parse_status: "numeric-out-of-range" })).toBe(true);
    expect(partial({ parse_status: "not-parsed" })).toBe(true);
    expect(partial({ decrypt_status: "unknown" })).toBe(false);
  });

  it("ignores container paths and source_path", () => {
    const types = (partial: Partial<GridRow>) => [...rowContentTypes(row({ rowKey: "c", ...partial }))];
    expect(types({ artifactType: "browser-history", sourcePath: "C:/x/places.sqlite" })).toEqual([]);
    expect(
      types({
        artifactType: "registry-run",
        sourcePath: "C:/x/NTUSER.DAT",
        fields: { details: { source_path: "C:/a.db" } },
      }),
    ).toEqual([]);
    expect(types({ artifactType: "file", sourcePath: "C:/x/a.pdf" })).toEqual(["document"]);
    expect(
      types({
        artifactType: "recent-shortcut",
        sourcePath: "C:/x/a.lnk",
        fields: { details: { target_path: "C:/a.zip" } },
      }),
    ).toEqual(["archive"]);
  });
});

describe("server-filtered counts", () => {
  it("files and timeline pages with conditions / flags take `matched`, null past the scan cap", async () => {
    installFetch({
      "/files": () =>
        jsonResponse({
          candidates: [{ path: "C:/a" }],
          matched: 7,
          total: 500,
          pagination: { matched: 7, has_more: true },
        }),
      "/timeline": () =>
        jsonResponse({
          events: [],
          matched: null,
          record_count: 900,
          pagination: { truncated: true, has_more: true },
        }),
    });
    const files = await fetchFilesPage("r", 0, 1, undefined, undefined, { conditions: { partial: "1" } });
    expect(files.total).toBe(7);
    const flagged = await fetchFilesPage("r", 0, 1, undefined, undefined, { ids: ["x"] });
    expect(flagged.total).toBe(7);
    const timeline = await fetchTimelinePage("r", 0, 1, undefined, { offhours: "1" });
    expect(timeline.total).toBeNull();
    expect(timeline.truncated).toBe(true);
  });
});

describe("F3 / F4 card list", () => {
  it("leaves modifier keys alone and resolves the active card by row key", () => {
    expect(isPlainKey({ ctrlKey: false, metaKey: false, altKey: false })).toBe(true);
    expect(isPlainKey({ ctrlKey: true, metaKey: false, altKey: false })).toBe(false);
    expect(isPlainKey({ ctrlKey: false, metaKey: false, altKey: true })).toBe(false);
    const rows = [row({ rowKey: "a" }), row({ rowKey: "b" }), row({ rowKey: "c" })];
    expect(resolveActiveIndex(rows, "c", 0)).toBe(2);
    expect(resolveActiveIndex([rows[2] as GridRow, rows[0] as GridRow], "c", 2)).toBe(0);
    expect(resolveActiveIndex(rows.slice(0, 1), "c", 2)).toBe(0);
    expect(resolveActiveIndex([], "c", 5)).toBe(0);
  });

  it("ignores Ctrl/Alt+J; the list forwards focus to an active card scrolled out of view", async () => {
    installFetch({ "/files": filesHandler(300) });
    render(<CardView />, { wrapper: queryWrapper().wrapper });
    const list = await screen.findByRole("list", { name: /행 카드 목록, 250건/ });
    const items = () => within(list).getAllByRole("listitem");
    act(() => items()[0]?.focus());
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "j", ctrlKey: true });
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "j", altKey: true });
    expect(document.activeElement?.getAttribute("data-card-index")).toBe("0");
    expect(list.getAttribute("tabindex")).toBeNull();
    // Scroll the active card out of the virtual window: the list becomes the tab stop.
    list.scrollTop = 200 * CARD_HEIGHT;
    fireEvent.scroll(list);
    await waitFor(() => expect(list.getAttribute("tabindex")).toBe("0"));
    act(() => list.focus());
    list.scrollTop = 0;
    fireEvent.scroll(list);
    await waitFor(() => expect(document.activeElement?.getAttribute("data-card-index")).toBe("0"));
  });
});

describe("F9 / F7 map states", () => {
  it("names the active conditions when nothing is located and stops scanning on a page error", async () => {
    useGridLocalStore.setState({
      route: { runId: "run-1", collection: { id: "artifacts", kind: "eventlog" }, q: "", rowRef: null },
    });
    useAppStore
      .getState()
      .patchRoute({ runId: "run-1", collection: "artifacts", kind: "eventlog", partial: true });
    installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            eventlog: { record_count: 9, matched: 0, pagination: { filtered: true }, artifacts: [] },
          },
        }),
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    expect(await screen.findByText("현재 조건에 맞는 행 중 위도·경도가 있는 행이 없습니다.")).toBeTruthy();
  });

  it("a failed next page ends the scan with a Korean error instead of an endless spinner", async () => {
    useGridLocalStore.setState({
      route: { runId: "run-1", collection: { id: "artifacts", kind: "eventlog" }, q: "", rowRef: null },
    });
    installFetch({
      "/artifacts": (url) =>
        Number(url.searchParams.get("offset") ?? 0) > 0
          ? jsonResponse({ detail: "서버 오류" }, 500)
          : jsonResponse({
              artifacts: {
                eventlog: {
                  record_count: 600,
                  matched: null,
                  pagination: { filtered: true, has_more: true, truncated: true, next_offset: 250 },
                  artifacts: Array.from({ length: 250 }, (_, index) => ({
                    artifact_type: "eventlog-event",
                    path: "C:/x.evtx",
                    record_index: index,
                    details: {},
                  })),
                },
              },
            }),
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    const alert = await screen.findByText(/위치 행을 더 불러오지 못했습니다/, {}, { timeout: 4000 });
    expect(alert.textContent).not.toContain("Error:");
    expect(screen.queryByText("위치 행을 찾는 중…")).toBeNull();
  });
});

describe("연결 그래프 without its centre node", () => {
  it("keeps one tab stop and ignores Ctrl+arrows", async () => {
    const graph: Graph = {
      run_id: "run-1",
      table: "people",
      label: "사람 식별자",
      source: {
        status: "completed",
        analysis_id: "a1",
        source: "run-stage",
        generated_at: null,
        coverage: "complete",
      },
      center: "v:people:missing",
      nodes: [
        {
          id: "r:eventlog:0",
          type: "row",
          kind: "eventlog",
          family: "eventlog-event",
          field: "target_user_name",
          artifact_type: "eventlog-event",
          record_index: 0,
          time: null,
          label: "eventlog-event #0",
          collection: "artifacts",
          locator: "/artifacts/0",
        },
        {
          id: "r:eventlog:1",
          type: "row",
          kind: "eventlog",
          family: "eventlog-event",
          field: "target_user_name",
          artifact_type: "eventlog-event",
          record_index: 1,
          time: null,
          label: "eventlog-event #1",
          collection: "artifacts",
          locator: "/artifacts/1",
        },
      ],
      edges: [],
      rows: 2,
      rows_read: 2,
      values: 0,
      dropped_values: 0,
      truncated: false,
      max_nodes: 200,
    };
    installFetch({ "/derived/people/graph": () => jsonResponse(graph) });
    render(
      <DerivedGraph runId="run-1" table="people" normalized="missing" timezone="utc" onNavigate={() => {}} />,
      {
        wrapper: queryWrapper().wrapper,
      },
    );
    await screen.findByRole("group", { name: /연결 그래프/ });
    const nodes = screen.getAllByRole("button");
    expect(nodes.filter((node) => node.getAttribute("tabindex") === "0")).toHaveLength(1);
    const first = nodes.find((node) => node.getAttribute("tabindex") === "0") as HTMLElement;
    act(() => first.focus());
    fireEvent.keyDown(first, { key: "ArrowDown", ctrlKey: true });
    expect(document.activeElement).toBe(first);
    fireEvent.keyDown(first, { key: "ArrowDown" });
    await waitFor(() => expect(document.activeElement).not.toBe(first));
  });
});
