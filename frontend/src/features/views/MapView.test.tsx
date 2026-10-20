// biome-ignore-all lint/a11y: tests drive ARIA widgets through their DOM roles
/**
 * r6 §3.3 갈래 C (Q-S3-9): the map view draws the server's clusters first (`GET /geo-clusters`,
 * located-row index), pages the coordinate table 500 rows at a time with `geo=`, says
 * "위치 색인 만드는 중" while an older run's index is building and asks again.
 */
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetCommandRegistry } from "../../commands/registry";
import { resetAppStore, useAppStore } from "../../state/store";
import { useGridLocalStore } from "../grid/adapter";
import { installFetch, jsonResponse, mockLayout, queryWrapper, resetGridStore } from "../grid/testSupport";
import type { GeoClustersPayload } from "./geo";
import { MAP_TABLE_PAGE, MapView } from "./MapView";

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
    expect(clusters[0]?.getAttribute("aria-label")).toMatch(/37\.4850° N, 126\.9450° E 부근 1500건/);
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

    // "더 불러오기" asks for the next 500-row page (the grid prefetches the one after it).
    fireEvent.click(screen.getByRole("button", { name: `좌표 표 ${MAP_TABLE_PAGE}건 더 불러오기` }));
    await waitFor(
      () => expect(screen.getByRole("table").querySelectorAll("tbody tr").length).toBeGreaterThan(500),
      { timeout: 5000 },
    );
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

  it("asks a category node's clusters with the category's kinds", async () => {
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
