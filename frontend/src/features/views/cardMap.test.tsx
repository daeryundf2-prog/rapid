// biome-ignore-all lint/a11y: tests drive ARIA widgets through their DOM roles
/** r4 §2.3: 행(카드) 보기 and 지도 대체 보기 — keyboard, a11y names, virtualisation, clusters. */
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetCommandRegistry } from "../../commands/registry";
import type { GridRow } from "../../contracts/collection";
import { KEY_MAP } from "../../contracts/command";
import { parseHash, serializeRoute } from "../../router";
import { resetAppStore, useAppStore } from "../../state/store";
import { inGeoBox, parseGeo } from "../filters/conditionValues";
import { useGridLocalStore } from "../grid/adapter";
import {
  filesHandler,
  installFetch,
  jsonResponse,
  mockLayout,
  queryWrapper,
  resetGridStore,
} from "../grid/testSupport";
import { VIEW_DEFS, viewAvailability, viewDisabledReason } from "./availability";
import { CARD_HEIGHT, CardView, cardAccessibleName, cardModel } from "./CardView";
import {
  CLUSTER_CELL_DEGREES,
  cellEdge,
  cellOf,
  clusterRows,
  formatCoordinates,
  geoRows,
  rowCoordinates,
} from "./geo";
import { MAP_POLICY_NOTE, MapView } from "./MapView";

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
  resetCommandRegistry();
  vi.unstubAllGlobals();
});

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

function renderQ(ui: React.ReactElement) {
  const { wrapper } = queryWrapper();
  return render(ui, { wrapper });
}

describe("view switch registration (cards · map)", () => {
  it("binds Alt+Shift+5 / 6 without clashing with any other key", () => {
    expect(KEY_MAP.viewCards).toBe("Alt+Shift+5");
    expect(KEY_MAP.viewMap).toBe("Alt+Shift+6");
    const values = Object.values(KEY_MAP);
    expect(new Set(values).size).toBe(values.length);
    expect(VIEW_DEFS.map((def) => def.id)).toEqual([
      "columns",
      "thumbnails",
      "chat",
      "histogram",
      "cards",
      "map",
    ]);
  });

  it("offers cards on row listings and the map on artifact nodes only", () => {
    expect(viewAvailability({ id: "artifacts", kind: "eventlog" }).cards).toBeUndefined();
    expect(viewAvailability({ id: "timeline" }).cards).toBeUndefined();
    expect(viewAvailability({ id: "files" }).cards).toBeUndefined();
    expect(viewDisabledReason("cards", { id: "review" })).toMatch(/행 목록 노드/);
    expect(viewAvailability({ id: "artifacts", kind: "media-image" }).map).toBeUndefined();
    expect(viewDisabledReason("map", { id: "files" })).toMatch(/아티팩트 노드/);
    for (const view of ["cards", "map"] as const) {
      const hash = serializeRoute({ runId: "r", collection: "artifacts", kind: "media-image", view });
      expect(parseHash(hash).view).toBe(view);
    }
  });
});

describe("cardModel", () => {
  it("builds title, Korean subtitle, right-aligned date and flag chips", () => {
    const model = cardModel(
      row({
        rowKey: "a",
        title: "Security 4624",
        artifactType: "eventlog-event",
        timestamp: "2025-05-26T10:30:00Z",
        sourcePath: "C:/Windows/System32/winevt/Logs/Security.evtx",
        reviewStatus: "relevant",
        tags: ["북마크"],
        fields: { flags: [{ id: "eventlog.log_cleared", grade: "A", label: "이벤트 로그 삭제" }] },
      }),
      "utc",
    );
    expect(model.title).toBe("Security 4624");
    expect(model.date).toBe("2025-05-26");
    expect(model.clock.startsWith("10:30")).toBe(true);
    expect(model.chips.map((chip) => chip.tone)).toEqual(["flag", "review", "tag"]);
    const name = cardAccessibleName(model, true);
    expect(name).toContain("Security 4624");
    expect(name).toContain("시각 2025-05-26");
    expect(name).toMatch(/특이사항 .*이벤트 로그 삭제/);
    expect(name.endsWith("선택됨")).toBe(true);
    expect(cardAccessibleName(cardModel(row({ rowKey: "b" }), "utc"), false)).toContain("시각 없음");
  });
});

describe("CardView", () => {
  it("is a virtualised a11y list with J/K, End, Enter, Space and inline actions", async () => {
    installFetch({ "/files": filesHandler(300) });
    render(<CardView />, { wrapper: queryWrapper().wrapper });
    const list = await screen.findByRole("list", { name: /행 카드 목록, 250건/ });
    const items = () => within(list).getAllByRole("listitem");
    // jsdom has no scrolling: move the scroll container the way the browser would after scrollToIndex.
    const scrollTo = (index: number) => {
      list.scrollTop = Math.max(0, index * CARD_HEIGHT - 400);
      fireEvent.scroll(list);
    };
    // Only the visible cards (+ overscan) are mounted.
    expect(items().length).toBeLessThan(Math.ceil(600 / CARD_HEIGHT) + 12);
    expect(items()[0]?.getAttribute("aria-setsize")).toBe("250");
    expect(items()[0]?.getAttribute("aria-posinset")).toBe("1");
    expect(items().filter((item) => item.tabIndex === 0)).toHaveLength(1);
    expect(items()[0]?.getAttribute("aria-label")).toMatch(/^file-0\.txt, .*시각 /);

    act(() => items()[0]?.focus());
    expect(useGridLocalStore.getState().target?.sourcePath).toBe("C:/evidence/dir0/file-0.txt");
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "j" });
    await waitFor(() => expect(document.activeElement?.getAttribute("data-card-index")).toBe("1"));
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "K" });
    await waitFor(() => expect(document.activeElement?.getAttribute("data-card-index")).toBe("0"));
    // End reaches the last loaded card; scrolling near the end pages the next rows in.
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "End" });
    scrollTo(249);
    await waitFor(() => expect(document.activeElement?.getAttribute("data-card-index")).toBe("249"));
    await waitFor(() => expect(list.getAttribute("aria-label")).toContain("300건"));
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "End" });
    scrollTo(299);
    await waitFor(() => expect(document.activeElement?.getAttribute("data-card-index")).toBe("299"));
    expect(document.activeElement?.getAttribute("aria-posinset")).toBe("300");
    expect(document.activeElement?.getAttribute("aria-setsize")).toBe("300");

    const before = useGridLocalStore.getState().viewerFocusRequests;
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "Enter" });
    expect(useGridLocalStore.getState().viewerFocusRequests).toBe(before + 1);
    expect(useGridLocalStore.getState().target?.sourcePath).toBe("C:/evidence/dir5/file-299.txt");
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: " " });
    expect(await screen.findByText("1개 선택")).toBeTruthy();

    // The active card's inline actions are named and reachable.
    const active = document.activeElement as HTMLElement;
    for (const name of [/file-299\.txt 인용 복사/, /file-299\.txt 원본 열기/, /file-299\.txt 북마크 태그/]) {
      const button = within(active).getByRole("button", { name });
      expect(button.tabIndex).toBe(0);
    }
    const writeText = vi.fn(async () => {});
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
    fireEvent.click(within(active).getByRole("button", { name: /인용 복사/ }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(String((writeText.mock.calls[0] as unknown[] | undefined)?.[0])).toContain(
      "[files:/candidates/299]",
    );
  });
});

describe("geo model", () => {
  const located = (key: string, lat: number, lon: number, time?: string) =>
    row({
      rowKey: key,
      timestamp: time ?? null,
      fields: { details: { gps_latitude: lat, gps_longitude: lon } },
    });

  it("reads coordinates like the server (gps_* · latitude · exif_gps_profile), (0,0) is none", () => {
    expect(rowCoordinates(located("a", 37.48, 126.95))).toEqual({ lat: 37.48, lon: 126.95 });
    expect(
      rowCoordinates(
        row({
          rowKey: "b",
          fields: { details: { exif_gps_profile: { latitude: "35.1", longitude: "129" } } },
        }),
      ),
    ).toEqual({ lat: 35.1, lon: 129 });
    expect(rowCoordinates(located("c", 0, 0))).toBeNull();
    expect(rowCoordinates(located("d", 91, 0))).toBeNull();
    expect(formatCoordinates(-33.8688, 151.2093)).toBe("33.8688° S, 151.2093° E");
  });

  it("clusters on the 0.01° grid with counts and first / last time", () => {
    const clusters = clusterRows(
      geoRows([
        located("a", 37.4812, 126.9497, "2021-10-28T07:01:19Z"),
        located("b", 37.4851, 126.9411, "2021-10-27T07:00:00Z"),
        located("c", 37.495, 126.9401, "2021-10-29T07:00:00Z"),
        located("d", 35.1, 129.04),
        row({ rowKey: "e" }),
      ]),
    );
    expect(CLUSTER_CELL_DEGREES).toBe(0.01);
    expect(clusters.map((cluster) => cluster.count)).toEqual([2, 1, 1]);
    const top = clusters[0];
    expect(top?.box).toBe("37.48,126.94,37.49,126.95");
    expect(top?.first).toBe("2021-10-27T07:00:00Z");
    expect(top?.last).toBe("2021-10-28T07:01:19Z");
  });

  it("uses the server cell rule (geo_index.cell_edge / cell_of): each box holds exactly its rows", () => {
    // Reference of the documented rule at 0.01°: edge(i) = round6(i * 0.01), exactly -limit for the
    // first cell and limit past the last; a value goes to the cell whose half-open box holds it,
    // limit itself in the last cell. Brute force over every cell, independent of `cellOf`.
    const refEdge = (index: number, limit: number) => {
      const last = Math.round(limit / 0.01) - 1;
      if (index <= -last - 1) return -limit;
      if (index > last) return limit;
      return Math.round(index * 0.01 * 1e6) / 1e6;
    };
    const refCell = (value: number, limit: number) => {
      const last = Math.round(limit / 0.01) - 1;
      for (let index = -last - 1; index <= last; index += 1) {
        const high = refEdge(index + 1, limit);
        if (value >= refEdge(index, limit) && (value < high || (index === last && value <= high)))
          return index;
      }
      throw new Error(`no cell for ${value}`);
    };
    const points: [string, number, number][] = [
      ["n-edge", 89.9995, 179.9999],
      ["s-edge", -89.9995, -180],
      ["just-below-cell", 0.0099999999995, -0.005],
      ["world-corner", 90, 180],
      ["seoul", 37.48, 126.94],
      ["neg-lat", -0.005, 179.9999],
      ["lat-0.01", 0.01, -180],
    ];
    // Values printed by rapidtriage.api.app.geo_index (cell_of / cell_edge / _number_text).
    const serverBoxes: Record<string, string> = {
      "n-edge": "89.99,179.99,90,180",
      "s-edge": "-90,-180,-89.99,-179.99",
      "just-below-cell": "0,-0.01,0.01,0",
      "world-corner": "89.99,179.99,90,180",
      seoul: "37.48,126.94,37.49,126.95",
      "neg-lat": "-0.01,179.99,0,180",
      "lat-0.01": "0.01,-180,0.02,-179.99",
    };
    const rows = points.map(([key, lat, lon]) => located(key, lat, lon));
    const clusters = clusterRows(geoRows(rows));
    for (const [key, lat, lon] of points) {
      const latCell = refCell(lat, 90);
      const lonCell = refCell(lon, 180);
      expect(cellOf(lat, 90)).toBe(latCell);
      expect(cellOf(lon, 180)).toBe(lonCell);
      const cluster = clusters.find((item) => item.rows.some((r) => r.rowKey === key));
      expect(cluster?.id).toBe(`${latCell}:${lonCell}`);
      const expected = [
        refEdge(latCell, 90),
        refEdge(lonCell, 180),
        refEdge(latCell + 1, 90),
        refEdge(lonCell + 1, 180),
      ];
      expect(cluster?.box).toBe(expected.join(","));
      expect(cluster?.box).toBe(serverBoxes[key]);
    }
    expect(cellEdge(-9000, 90)).toBe(-90);
    expect(cellEdge(9000, 90)).toBe(90);
    expect(cellEdge(18000, 180)).toBe(180);
    // Every cluster's geo= box holds exactly its own rows under the client in-box check.
    for (const cluster of clusters) {
      const box = parseGeo(cluster.box);
      expect(box).not.toBeNull();
      const inside = rows
        .filter((r) => {
          const point = rowCoordinates(r);
          return point !== null && inGeoBox(point, box as [number, number, number, number]);
        })
        .map((r) => r.rowKey)
        .sort();
      expect(inside).toEqual(cluster.rows.map((r) => r.rowKey).sort());
    }
  });
});

describe("MapView", () => {
  it("asks the server for located rows only, lists clusters and a coordinate table; a cluster filters the grid", async () => {
    useGridLocalStore.setState({
      route: { runId: "run-1", collection: { id: "artifacts", kind: "media-image" }, q: "", rowRef: null },
    });
    useAppStore
      .getState()
      .patchRoute({ runId: "run-1", collection: "artifacts", kind: "media-image", view: "map" });
    const calls = installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            "media-image": {
              record_count: 5,
              matched: 3,
              pagination: { filtered: true, has_more: false, matched: 3 },
              artifacts: [
                {
                  artifact_type: "media-image",
                  path: "C:/p/a.jpg",
                  record_index: 0,
                  details: {
                    gps_latitude: 37.4812384,
                    gps_longitude: 126.9497216,
                    gps_timestamp: "2021-10-28T07:01:19Z",
                  },
                },
                {
                  artifact_type: "media-image",
                  path: "C:/p/b.jpg",
                  record_index: 1,
                  details: { gps_latitude: 37.4812384, gps_longitude: 126.9497216 },
                },
                {
                  artifact_type: "media-image",
                  path: "C:/p/c.jpg",
                  record_index: 4,
                  details: { gps_latitude: 35.1, gps_longitude: 129.04 },
                },
              ],
            },
          },
        }),
    });
    renderQ(<MapView />);
    const list = await screen.findByRole("list", { name: /근접 묶음/ });
    expect(calls.some((call) => call.url.includes("geo=-90%2C-180%2C90%2C180"))).toBe(true);
    expect(screen.getByRole("note").textContent).toBe(MAP_POLICY_NOTE);
    expect(screen.getByRole("table").querySelectorAll("tbody tr")).toHaveLength(3);
    const clusters = within(list).getAllByRole("button");
    expect(clusters).toHaveLength(2);
    expect(clusters[0]?.getAttribute("aria-label")).toMatch(/37\.4850° N, 126\.9450° E 부근 2건/);
    fireEvent.click(clusters[0] as HTMLElement);
    const route = useAppStore.getState().route;
    expect(route.geo).toBe("37.48,126.94,37.49,126.95");
    expect(route.view).toBeUndefined();
  });

  it("says why it is empty and that no map service is called", async () => {
    useGridLocalStore.setState({
      route: { runId: "run-1", collection: { id: "artifacts", kind: "eventlog" }, q: "", rowRef: null },
    });
    installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            eventlog: { record_count: 9, matched: 0, pagination: { filtered: true }, artifacts: [] },
          },
        }),
    });
    renderQ(<MapView />);
    expect(await screen.findByText("이 노드에는 위도·경도가 있는 행이 없습니다.")).toBeTruthy();
    expect(screen.getByText(/외부 지도 서비스는 쓰지 않습니다/)).toBeTruthy();
  });
});
