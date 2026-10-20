// biome-ignore-all lint/a11y: tests drive ARIA widgets through their DOM roles
/**
 * r6 §3.3 갈래 C (Q-S3-9): the map view draws the server's clusters first (`GET /geo-clusters`,
 * located-row index), pages the coordinate table 500 rows at a time with `geo=`, says
 * "위치 색인 만드는 중" while an older run's index is building and asks again.
 */
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetArtifactCountsCache } from "../../api/collections";
import { resetCommandRegistry } from "../../commands/registry";
import { resetAppStore, useAppStore } from "../../state/store";
import { useFilterStore } from "../filters/filterStore";
import { useGridLocalStore } from "../grid/adapter";
import { installFetch, jsonResponse, mockLayout, queryWrapper, resetGridStore } from "../grid/testSupport";
import type { GeoClustersPayload } from "./geo";
import { MAP_CLUSTER_PAGE, MAP_TABLE_PAGE, MapView } from "./MapView";
import { GEO_INDEX_POLL_LIMIT_MS } from "./useViewRows";

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

const READY: GeoClustersPayload = {
  geo_index: "ready",
  geo_index_source: "file",
  cell: 0.01,
  kinds: ["media-image"],
  available_kinds: ["browser", "media-image", "synthetic-media"],
  located_total: 2000,
  matched: 2000,
  clusters: [
    {
      id: "3748:12694",
      box: "37.48,126.94,37.49,126.95",
      lat: 37.485,
      lon: 126.945,
      count: 1500,
      first_time: "2021-10-27T07:00:00Z",
      last_time: "2021-10-28T07:01:19Z",
      sample: { kind: "media-image", record_index: 3, lat: 37.4812, lon: 126.9497, time: null },
    },
    {
      id: "3510:12904",
      box: "35.1,129.04,35.11,129.05",
      lat: 35.105,
      lon: 129.045,
      count: 500,
      first_time: null,
      last_time: null,
    },
  ],
  clusters_total: 2,
  clusters_truncated: false,
  truncated: false,
  filtered: false,
};

/** `/tree` of a run with three artifact kinds (two of them in the 미디어 category). */
const RUN_TREE = {
  nodes: [
    {
      id: "artifacts",
      label: "아티팩트",
      count: 3,
      collection: "artifacts",
      children: ["browser", "media-image", "synthetic-media"].map((kind) => ({
        id: `artifacts:${kind}`,
        label: kind,
        count: 1,
        collection: "artifacts",
        kind,
      })),
    },
  ],
};

function located(index: number) {
  return {
    artifact_type: "media-image",
    path: `C:/p/${index}.jpg`,
    record_index: index,
    details: { gps_latitude: 37.4812, gps_longitude: 126.9497 },
  };
}

/** A kind page of `limit` located rows starting at `offset` (2,000 located rows in all). */
function kindPage(url: URL) {
  const offset = Number(url.searchParams.get("offset") ?? 0);
  const limit = Number(url.searchParams.get("limit") ?? 0);
  const count = Math.max(0, Math.min(limit, 2000 - offset));
  return jsonResponse({
    artifacts: {
      "media-image": {
        record_count: 640_000,
        matched: 2000,
        pagination: { filtered: true, has_more: offset + count < 2000, matched: 2000 },
        artifacts: Array.from({ length: count }, (_, i) => located(offset + i)),
      },
    },
  });
}

function kindRoute(kind = "media-image") {
  useGridLocalStore.setState({
    route: { runId: "run-1", collection: { id: "artifacts", kind }, q: "", rowRef: null },
  });
  useAppStore.getState().patchRoute({ runId: "run-1", collection: "artifacts", kind, view: "map" });
}

describe("MapView with the located-row index", () => {
  it("draws server clusters, pages the table 500 rows at a time and never autoloads 20,000 rows", async () => {
    kindRoute();
    const calls = installFetch({ "/geo-clusters": () => jsonResponse(READY), "/artifacts": kindPage });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    const list = await screen.findByRole("list", { name: /근접 묶음/ }, { timeout: 5000 });
    const clusters = within(list).getAllByRole("button");
    expect(clusters).toHaveLength(2);
    expect(clusters[0]?.getAttribute("aria-label")).toMatch(/37\.4850° N, 126\.9450° E 부근 1,500건/);
    await waitFor(() => expect(screen.getByRole("table").querySelectorAll("tbody tr")).toHaveLength(500), {
      timeout: 5000,
    });
    expect(screen.getByText(/위치 행 2,000건 · 묶음 2개/)).toBeTruthy();

    const clusterCall = calls.find((call) => call.url.includes("/geo-clusters"));
    expect(clusterCall?.url).toContain("kind=media-image");
    expect(clusterCall?.url).toContain("geo=-90%2C-180%2C90%2C180");
    expect(clusterCall?.url).toContain("cell=0.01");
    const pages = () => calls.filter((call) => call.url.includes("/artifacts"));
    expect(pages()).toHaveLength(1);
    expect(pages()[0]?.url).toContain(`limit=${MAP_TABLE_PAGE}`);
    expect(pages()[0]?.url).toContain("geo=-90%2C-180%2C90%2C180");
    // Nothing else is fetched on its own (the old view paged up to 20,000 rows).
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(pages()).toHaveLength(1);

    // "500건 더 불러오기" asks for exactly the next 500-row page (no prefetch of the one after it).
    fireEvent.click(screen.getByRole("button", { name: `좌표 표 ${MAP_TABLE_PAGE}건 더 불러오기` }));
    await waitFor(() => expect(screen.getByRole("table").querySelectorAll("tbody tr")).toHaveLength(1000), {
      timeout: 5000,
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(pages()).toHaveLength(2);
    expect(screen.getByRole("table").querySelectorAll("tbody tr")).toHaveLength(1000);
    expect(pages()[1]?.url).toContain(`offset=${MAP_TABLE_PAGE}`);
    for (const page of pages()) expect(page.url).toContain(`limit=${MAP_TABLE_PAGE}`);

    // A server cluster filters the grid to its box like before.
    fireEvent.click(clusters[1] as HTMLElement);
    expect(useAppStore.getState().route.geo).toBe("35.1,129.04,35.11,129.05");
  }, 20_000);

  it("says the index is being built, then asks again and draws the server clusters", async () => {
    kindRoute();
    let clusterCalls = 0;
    installFetch({
      "/geo-clusters": () => {
        clusterCalls += 1;
        return jsonResponse(
          clusterCalls === 1
            ? {
                ...READY,
                geo_index: "building",
                clusters: [],
                clusters_total: 0,
                matched: null,
                located_total: null,
              }
            : READY,
        );
      },
      "/artifacts": kindPage,
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    expect(await screen.findByText(/위치 색인 만드는 중… 끝나면/)).toBeTruthy();
    // Meanwhile the loaded rows are clustered by the console.
    expect(screen.getByText("근접 묶음 (0.01° 격자)")).toBeTruthy();
    await waitFor(() => expect(screen.getByText(/위치 행 2,000건 · 묶음 2개/)).toBeTruthy(), {
      timeout: 4000,
    });
    expect(clusterCalls).toBeGreaterThanOrEqual(2);
    expect(screen.queryByText(/위치 색인 만드는 중/)).toBeNull();
  });

  it("is empty from the server count alone and says so", async () => {
    kindRoute("eventlog");
    installFetch({
      "/geo-clusters": () =>
        jsonResponse({
          ...READY,
          kinds: ["eventlog"],
          clusters: [],
          clusters_total: 0,
          matched: 0,
          located_total: 0,
        }),
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            eventlog: { record_count: 9, matched: 0, pagination: { filtered: true }, artifacts: [] },
          },
        }),
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    expect(await screen.findByText("이 노드에는 위도·경도가 있는 행이 없습니다.")).toBeTruthy();
  });

  it("asks a category node's clusters once, with the category's kinds from the run tree", async () => {
    useGridLocalStore.setState({
      route: { runId: "run-1", collection: { id: "artifacts", category: "media" }, q: "", rowRef: null },
    });
    const calls = installFetch({
      "/geo-clusters": () => jsonResponse(READY),
      "/artifacts": () => jsonResponse({ artifacts: {} }),
      "/tree": () => jsonResponse(RUN_TREE),
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    await screen.findByRole("list", { name: /근접 묶음/ });
    const clusterUrls = calls.filter((call) => call.url.includes("/geo-clusters")).map((call) => call.url);
    expect(clusterUrls).toHaveLength(1);
    expect(clusterUrls[0]).toContain("kind=media-image&kind=synthetic-media");
  });

  it("without the run tree, asks the run's kinds first and then the category's kinds", async () => {
    useGridLocalStore.setState({
      route: { runId: "run-1", collection: { id: "artifacts", category: "media" }, q: "", rowRef: null },
    });
    const calls = installFetch({
      "/geo-clusters": () => jsonResponse(READY),
      "/artifacts": () => jsonResponse({ artifacts: {} }),
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    await screen.findByRole("list", { name: /근접 묶음/ });
    const clusterUrls = calls.filter((call) => call.url.includes("/geo-clusters")).map((call) => call.url);
    expect(clusterUrls).toHaveLength(2);
    expect(clusterUrls[0]).not.toContain("kind=");
    expect(clusterUrls[1]).toContain("kind=media-image&kind=synthetic-media");
  });

  it("falls back to the loaded rows when the server has no clusters", async () => {
    kindRoute();
    installFetch({
      "/geo-clusters": () =>
        jsonResponse({ ...READY, geo_index: "unavailable", clusters: [], matched: null }),
      "/artifacts": kindPage,
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    expect(await screen.findByText("불러온 행 기준 묶음입니다.")).toBeTruthy();
    const list = screen.getByRole("list", { name: /근접 묶음/ });
    expect(within(list).getAllByRole("button")).toHaveLength(1);
    expect(within(list).getAllByRole("button")[0]?.getAttribute("aria-label")).toMatch(/부근 500건/);
  });
});

/** A kind page over `rows(offset, count)` (2,000 rows); `fail(offset)` answers 500 for that page. */
function pagedRoute(fail: (offset: number) => boolean = () => false) {
  return (url: URL) => {
    const offset = Number(url.searchParams.get("offset") ?? 0);
    if (fail(offset)) return jsonResponse({ detail: "boom" }, 500);
    return kindPage(url);
  };
}

describe("MapView console review fixes", () => {
  it("clusters the loaded rows when the search text has several words (the server sees only one word)", async () => {
    kindRoute();
    useGridLocalStore.setState({
      route: {
        runId: "run-1",
        collection: { id: "artifacts", kind: "media-image" },
        q: "p/1 jpg",
        rowRef: null,
      },
    });
    const calls = installFetch({ "/geo-clusters": () => jsonResponse(READY), "/artifacts": kindPage });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    const list = await screen.findByRole("list", { name: /근접 묶음/ }, { timeout: 5000 });
    // Rows 1, 10-19 and 100-199 of the first page match both words: 111 rows in table and cluster.
    await waitFor(() => expect(screen.getByRole("table").querySelectorAll("tbody tr")).toHaveLength(111));
    const buttons = within(list).getAllByRole("button");
    expect(buttons).toHaveLength(1);
    expect(buttons[0]?.getAttribute("aria-label")).toMatch(/부근 111건/);
    expect(screen.getByText(/위치 행 111건 · 묶음 1개/)).toBeTruthy();
    expect(screen.getByText(/검색어·필터 일부를 서버 묶음에 반영할 수 없어/)).toBeTruthy();
    expect(calls.some((call) => call.url.includes("/geo-clusters"))).toBe(false);
  });

  it("clusters the loaded rows when a one-word search sits next to a 경로 filter", async () => {
    kindRoute();
    useGridLocalStore.setState({
      route: { runId: "run-1", collection: { id: "artifacts", kind: "media-image" }, q: "p/1", rowRef: null },
    });
    useFilterStore.getState().patchFilters({ path: "C:/p" });
    const calls = installFetch({ "/geo-clusters": () => jsonResponse(READY), "/artifacts": kindPage });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    await waitFor(() => expect(screen.getByRole("table").querySelectorAll("tbody tr")).toHaveLength(111), {
      timeout: 5000,
    });
    expect(screen.getByText(/위치 행 111건 · 묶음 1개/)).toBeTruthy();
    expect(calls.some((call) => call.url.includes("/geo-clusters"))).toBe(false);
  });

  it("still asks the server for a one-word search (sent as path_contains)", async () => {
    kindRoute();
    useGridLocalStore.setState({
      route: { runId: "run-1", collection: { id: "artifacts", kind: "media-image" }, q: "jpg", rowRef: null },
    });
    const calls = installFetch({ "/geo-clusters": () => jsonResponse(READY), "/artifacts": kindPage });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    await screen.findByText(/위치 행 2,000건 · 묶음 2개/, undefined, { timeout: 5000 });
    expect(calls.find((call) => call.url.includes("/geo-clusters"))?.url).toContain("path_contains=jpg");
  });

  it("shows the table error with 재시도 even when the server clusters are ready", async () => {
    kindRoute();
    let failing = true;
    installFetch({ "/geo-clusters": () => jsonResponse(READY), "/artifacts": pagedRoute(() => failing) });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    const alert = await screen.findByRole("alert", undefined, { timeout: 5000 });
    expect(alert.textContent).toMatch(/좌표 표를 불러오지 못했습니다/);
    // The clusters are still drawn from the server.
    expect(within(screen.getByRole("list", { name: /근접 묶음/ })).getAllByRole("button")).toHaveLength(2);
    failing = false;
    fireEvent.click(within(alert).getByRole("button", { name: "재시도" }));
    await waitFor(() => expect(screen.getByRole("table").querySelectorAll("tbody tr")).toHaveLength(500), {
      timeout: 5000,
    });
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("keeps 더 불러오기 focused and busy while its page loads, and offers a real retry after a failed page", async () => {
    kindRoute();
    let failing = true;
    const calls = installFetch({
      "/geo-clusters": () => jsonResponse(READY),
      "/artifacts": pagedRoute((offset) => offset === MAP_TABLE_PAGE && failing),
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    await waitFor(() => expect(screen.getByRole("table").querySelectorAll("tbody tr")).toHaveLength(500), {
      timeout: 5000,
    });
    const more = screen.getByRole("button", { name: `좌표 표 ${MAP_TABLE_PAGE}건 더 불러오기` });
    more.focus();
    fireEvent.click(more);
    // Same element, still in the document, focused, busy.
    await waitFor(() => expect(more.getAttribute("aria-busy")).toBe("true"));
    expect(more.getAttribute("aria-disabled")).toBe("true");
    expect(more.isConnected).toBe(true);
    expect(document.activeElement).toBe(more);
    // The page fails (server errors get one retry): the button now retries instead of doing nothing.
    await waitFor(() => expect(more.textContent).toBe("좌표 표 다시 불러오기"), { timeout: 5000 });
    expect(more.getAttribute("aria-busy")).toBeNull();
    expect(document.activeElement).toBe(more);
    expect(screen.getByRole("alert").textContent).toMatch(/좌표 표를 더 불러오지 못했습니다/);
    const pageCalls = () =>
      calls.filter((call) => call.url.includes("/artifacts") && call.url.includes("offset=500"));
    const before = pageCalls().length;
    failing = false;
    fireEvent.click(more);
    await waitFor(() => expect(screen.getByRole("table").querySelectorAll("tbody tr")).toHaveLength(1000), {
      timeout: 5000,
    });
    expect(pageCalls().length).toBeGreaterThan(before);
    expect(screen.queryByRole("alert")).toBeNull();
  }, 20_000);

  it("moves focus to the table title when the last page arrives and 더 불러오기 goes away", async () => {
    kindRoute();
    installFetch({
      "/geo-clusters": () => jsonResponse({ ...READY, matched: 600 }),
      "/artifacts": (url: URL) => {
        const offset = Number(url.searchParams.get("offset") ?? 0);
        const count = Math.max(0, Math.min(MAP_TABLE_PAGE, 600 - offset));
        return jsonResponse({
          artifacts: {
            "media-image": {
              record_count: 9000,
              matched: 600,
              pagination: { filtered: true, has_more: offset + count < 600, matched: 600 },
              artifacts: Array.from({ length: count }, (_, i) => located(offset + i)),
            },
          },
        });
      },
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    const more = await screen.findByRole(
      "button",
      { name: `좌표 표 ${MAP_TABLE_PAGE}건 더 불러오기` },
      { timeout: 5000 },
    );
    more.focus();
    fireEvent.click(more);
    await waitFor(() => expect(screen.getByRole("table").querySelectorAll("tbody tr")).toHaveLength(600), {
      timeout: 5000,
    });
    await waitFor(() => expect(more.isConnected).toBe(false));
    expect(document.activeElement?.id).toBe("map-table-title");
  }, 20_000);

  it("tells the 10,000-cluster limit apart from the index / filter read cap", async () => {
    kindRoute();
    installFetch({
      "/geo-clusters": () => jsonResponse({ ...READY, clusters_total: 12_345, clusters_truncated: true }),
      "/artifacts": kindPage,
    });
    const view = render(<MapView />, { wrapper: queryWrapper().wrapper });
    expect(
      await screen.findByText("묶음이 많아 처음 2개만 받았습니다(전체 12,345개).", undefined, {
        timeout: 5000,
      }),
    ).toBeTruthy();
    expect(screen.queryByText(/일부 행만 묶었습니다/)).toBeNull();
    expect(screen.getByText(/위치 행 2,000건 · 묶음 12,345개/)).toBeTruthy();
    view.unmount();

    installFetch({
      "/geo-clusters": () => jsonResponse({ ...READY, truncated: true }),
      "/artifacts": kindPage,
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    expect(await screen.findByText(/일부 행만 묶었습니다/, undefined, { timeout: 5000 })).toBeTruthy();
    expect(screen.queryByText(/묶음이 많아/)).toBeNull();
    expect(screen.getByText(/위치 행 2,000건 이상 · 묶음 2개/)).toBeTruthy();
  });

  it("draws 300 cluster buttons first and the rest on 묶음 더 보기 (focus on the first new one)", async () => {
    kindRoute();
    const many = Array.from({ length: MAP_CLUSTER_PAGE + 50 }, (_, i) => ({
      id: `${i}:0`,
      box: `${i / 100},0,${(i + 1) / 100},0.01`,
      lat: i / 100 + 0.005,
      lon: 0.005,
      count: 1,
      first_time: null,
      last_time: null,
    }));
    installFetch({
      "/geo-clusters": () => jsonResponse({ ...READY, clusters: many, clusters_total: many.length }),
      "/artifacts": kindPage,
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    const list = await screen.findByRole("list", { name: /근접 묶음/ }, { timeout: 5000 });
    await waitFor(() => expect(within(list).getAllByRole("button")).toHaveLength(MAP_CLUSTER_PAGE));
    fireEvent.click(screen.getByRole("button", { name: /묶음 50개 더 보기/ }));
    await waitFor(() => expect(within(list).getAllByRole("button")).toHaveLength(MAP_CLUSTER_PAGE + 50));
    expect(document.activeElement).toBe(within(list).getAllByRole("button")[MAP_CLUSTER_PAGE]);
    expect(screen.queryByRole("button", { name: /묶음 .*더 보기/ })).toBeNull();
  }, 20_000);

  it("does not say the node is empty when the server counts 0 but the listing has located rows", async () => {
    kindRoute();
    installFetch({
      "/geo-clusters": () =>
        jsonResponse({ ...READY, clusters: [], clusters_total: 0, matched: 0, located_total: 0 }),
      "/artifacts": kindPage,
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    await waitFor(() => expect(screen.getByRole("table").querySelectorAll("tbody tr")).toHaveLength(500), {
      timeout: 5000,
    });
    expect(screen.queryByText(/위도·경도가 있는 행이 없습니다/)).toBeNull();
    expect(screen.getByText("불러온 행 기준 묶음입니다.")).toBeTruthy();
    expect(within(screen.getByRole("list", { name: /근접 묶음/ })).getAllByRole("button")).toHaveLength(1);
  });

  it("says 묶음 불러오는 중 while the server clusters are on their way", async () => {
    kindRoute();
    let answer: (response: Response) => void = () => {};
    installFetch({
      "/geo-clusters": () => new Promise<Response>((resolve) => (answer = resolve)),
      "/artifacts": kindPage,
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    expect(await screen.findByText("묶음 불러오는 중…", undefined, { timeout: 5000 })).toBeTruthy();
    expect(screen.queryByText("불러온 행 기준 묶음입니다.")).toBeNull();
    expect(screen.queryByRole("list", { name: /근접 묶음/ })).toBeNull();
    answer(jsonResponse(READY));
    await screen.findByText(/위치 행 2,000건 · 묶음 2개/);
    expect(screen.queryByText("묶음 불러오는 중…")).toBeNull();
  });

  it("stops polling a building index after 5 minutes and keeps the loaded-row clusters", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      kindRoute();
      let clusterCalls = 0;
      installFetch({
        "/geo-clusters": () => {
          clusterCalls += 1;
          return jsonResponse({
            ...READY,
            geo_index: "building",
            clusters: [],
            clusters_total: 0,
            matched: null,
          });
        },
        "/artifacts": kindPage,
      });
      render(<MapView />, { wrapper: queryWrapper().wrapper });
      await screen.findByText(/위치 색인 만드는 중… 끝나면/);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(GEO_INDEX_POLL_LIMIT_MS + 2000);
      });
      expect(await screen.findByText(/위치 색인이 5분 안에 끝나지 않아/)).toBeTruthy();
      expect(screen.queryByText(/위치 색인 만드는 중… 끝나면/)).toBeNull();
      const stopped = clusterCalls;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(10_000);
      });
      expect(clusterCalls).toBe(stopped);
    } finally {
      vi.useRealTimers();
    }
  }, 30_000);

  it("notes a coordinate table that did not come from the located-row index (cross_kind.geo_index)", async () => {
    resetArtifactCountsCache();
    useGridLocalStore.setState({
      route: { runId: "run-1", collection: { id: "artifacts", category: "media" }, q: "", rowRef: null },
    });
    installFetch({
      "/geo-clusters": () => jsonResponse({ ...READY, geo_index: "building", clusters: [], matched: null }),
      "/tree": () => jsonResponse(RUN_TREE),
      "/artifacts": (url: URL) =>
        url.searchParams.get("geo")
          ? jsonResponse({
              artifacts: { "media-image": { artifacts: [located(0), located(1)] } },
              cross_kind: {
                order: [
                  ["media-image", 0],
                  ["media-image", 1],
                ],
                next_after: null,
                matched: 2,
                geo_index: "building",
              },
            })
          : jsonResponse({
              artifacts: {
                "media-image": { record_count: 2, artifacts: [] },
                "synthetic-media": { record_count: 0, artifacts: [] },
              },
            }),
    });
    render(<MapView />, { wrapper: queryWrapper().wrapper });
    expect(
      await screen.findByText(/좌표 표: 위치 색인을 만드는 중이라 서버가 행을 직접 훑었습니다/, undefined, {
        timeout: 5000,
      }),
    ).toBeTruthy();
    expect(screen.getByRole("table").querySelectorAll("tbody tr")).toHaveLength(2);
  });
});
