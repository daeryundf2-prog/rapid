// T-020 (WB-3, GAP-031·033, QA-021·022): partial-result band and honest empty states. Fixture
// payloads follow the T-019 list contract (`pagination.total_lower_bound`, `budget_stopped`,
// top-level `notice`). A budget-stopped scan shows the amber band and never "표시할 행이 없습니다";
// an uncounted total reads "n건 이상"; "세는 중" only while a request runs.
// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
import { cleanup, configure, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchArtifactsPage, resetArtifactCountsCache } from "../../api/collections";
import { resetCommandRegistry } from "../../commands/registry";
import { EMPTY_ROUTE, parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import { useFilterStore } from "../filters/filterStore";
import { useGridLocalStore } from "./adapter";
import { DataGrid } from "./DataGrid";
import { footerTotalText, GridFooter } from "./GridToolbar";
import { installFetch, jsonResponse, mockLayout, renderWithClient, resetGridStore } from "./testSupport";

configure({ asyncUtilTimeout: 5000 });

vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: vi.fn(),
}));

const RUN = "run-1";
const KIND = "windows-filesystem";
const BUDGET_MESSAGE = "시간 제한(0.01초) 안에 512행까지만 확인했습니다";
let restoreLayout: () => void = () => undefined;

const dataRows = () => screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index"));

function openKind(types: string[] = ["mft-entry"]) {
  const hash = `#/case/${RUN}/explore/artifacts/${KIND}`;
  window.location.hash = hash;
  useAppStore.getState().syncRouteFromLocation(parseHash(hash));
  useGridLocalStore.setState((s) => ({
    route: { ...s.route, runId: RUN, collection: { id: "artifacts", kind: KIND }, q: "", rowRef: null },
  }));
  if (types.length) useFilterStore.getState().patchFilters({ types });
}

function mftRows(from: number, to: number) {
  return Array.from({ length: to - from }, (_, i) => ({
    record_index: from + i,
    artifact_type: "mft-entry",
    path: `C:/Windows/file-${from + i}.dll`,
    timestamp: "2026-03-01T00:00:00Z",
  }));
}

/** One filtered kind page of `GET /artifacts` (artifact_filter.filter_artifact_page shape). */
function kindPage(options: {
  rows?: ReturnType<typeof mftRows>;
  total: number | null;
  lowerBound: number;
  hasMore?: boolean;
  truncated?: boolean;
  budgetStopped?: boolean;
  scanned?: number;
  notice?: { code: string; message: string };
}) {
  const rows = options.rows ?? [];
  return {
    artifacts: {
      [KIND]: {
        artifacts: rows,
        record_count: 40_024,
        matched: options.total,
        pagination: {
          collection: "artifacts",
          offset: 0,
          limit: 250,
          returned: rows.length,
          total: options.total,
          total_lower_bound: options.lowerBound,
          has_more: options.hasMore ?? false,
          filtered: true,
          scanned: options.scanned ?? 512,
          truncated: options.truncated ?? false,
          budget_stopped: options.budgetStopped ?? false,
        },
        ...(options.notice ? { notice: options.notice } : {}),
      },
    },
  };
}

const BUDGET_PAGE = kindPage({
  total: null,
  lowerBound: 0,
  budgetStopped: true,
  notice: { code: "SCAN_BUDGET_STOPPED", message: BUDGET_MESSAGE },
});

beforeEach(() => {
  resetCommandRegistry();
  resetGridStore();
  resetArtifactCountsCache();
  window.localStorage.clear();
  useAppStore.setState({ route: { ...EMPTY_ROUTE }, runs: [] });
  useFilterStore.getState().clearFilters();
  restoreLayout = mockLayout();
});
afterEach(() => {
  cleanup();
  restoreLayout();
  vi.unstubAllGlobals();
  resetCommandRegistry();
  window.localStorage.clear();
});

describe("collections: T-019 partial fields reach the page", () => {
  it("a budget-stopped kind page carries budgetStopped, notice and the lower bound", async () => {
    installFetch({ "/artifacts": () => jsonResponse(BUDGET_PAGE) });
    const page = await fetchArtifactsPage(RUN, KIND, 0, 250, undefined, undefined, undefined, undefined, [
      "mft-entry",
    ]);
    expect(page).toMatchObject({
      rows: [],
      total: null,
      budgetStopped: true,
      totalLowerBound: 0,
      notice: { code: "SCAN_BUDGET_STOPPED", message: BUDGET_MESSAGE },
    });
  });

  it("a budget-stopped cross-kind window is not 'exhausted': no count of 0, no chained requests", async () => {
    const calls = installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: { [KIND]: { artifacts: [], record_count: 40_024 } },
          cross_kind: {
            kinds: [KIND],
            order: [],
            matched: null,
            total: null,
            total_lower_bound: 0,
            has_more: true,
            next_after: null,
            scanned: 512,
            truncated: false,
            budget_stopped: true,
          },
          notice: { code: "SCAN_BUDGET_STOPPED", message: BUDGET_MESSAGE },
        }),
    });
    const page = await fetchArtifactsPage(
      RUN,
      undefined,
      0,
      250,
      undefined,
      undefined,
      undefined,
      undefined,
      ["mft-entry"],
    );
    expect(page.total).toBeNull();
    expect(page.budgetStopped).toBe(true);
    expect(page.notice?.code).toBe("SCAN_BUDGET_STOPPED");
    expect(page.hasMore).toBe(false);
    expect(calls.filter((c) => c.url.includes("/artifacts")).length).toBe(1);
  });
});

describe("grid: budget-stopped scan", () => {
  it("shows the amber band with the server message, never the 'no rows' empty state", async () => {
    openKind();
    installFetch({ "/artifacts": () => jsonResponse(BUDGET_PAGE) });
    renderWithClient(<DataGrid />);
    const band = await screen.findByTestId("r8-partial-banner");
    expect(band.getAttribute("data-code")).toBe("SCAN_BUDGET_STOPPED");
    expect(band.getAttribute("role")).toBe("status");
    expect(band.textContent).toContain("시간 제한으로 일부만 확인했습니다(512행 확인)");
    expect(band.textContent).toContain(BUDGET_MESSAGE);
    const empty = screen.getByTestId("grid-empty");
    expect(empty.textContent).not.toContain("표시할 행이 없습니다");
    expect(empty.textContent).not.toContain("조건에 맞는 행이 없습니다");
    expect(empty.textContent).toContain("시간 제한으로 일부만 확인했습니다");
    await waitFor(() => expect(screen.getByTestId("grid-footer-total").textContent).toBe("총 0건 이상"));
  });

  it("다시 시도 sends the same request again", async () => {
    openKind();
    const calls = installFetch({ "/artifacts": () => jsonResponse(BUDGET_PAGE) });
    renderWithClient(<DataGrid />);
    await screen.findByTestId("r8-partial-banner");
    const listCalls = () => calls.filter((c) => c.url.includes("/artifacts")).map((c) => c.url);
    await waitFor(() => expect(screen.getByTestId("r8-partial-retry")).not.toHaveProperty("disabled", true));
    const before = listCalls();
    fireEvent.click(screen.getByTestId("r8-partial-retry"));
    await waitFor(() => expect(listCalls().length).toBeGreaterThan(before.length));
    // The retry re-sends the stopped page's request unchanged.
    expect(listCalls().slice(before.length)).toContain(before[0]);
  });

  it("조건 좁히기 opens the column filter row", async () => {
    openKind();
    installFetch({ "/artifacts": () => jsonResponse(BUDGET_PAGE) });
    renderWithClient(<DataGrid />);
    await screen.findByTestId("r8-partial-banner");
    fireEvent.click(screen.getByTestId("r8-partial-narrow"));
    await waitFor(() => expect(screen.queryByTestId("grid-colfilter-row")).not.toBeNull());
  });
});

describe("grid: uncounted, truncated and complete pages", () => {
  it("an uncounted page reads 'n건 이상' (largest server bound) and has no band", async () => {
    openKind();
    installFetch({
      "/artifacts": (url) => {
        const offset = Number(url.searchParams.get("offset") ?? 0);
        const page = kindPage({
          rows: mftRows(offset, offset + 250),
          total: null,
          lowerBound: offset + 251,
          hasMore: true,
          notice: {
            code: "TOTAL_NOT_COUNTED",
            message: `전체 건수는 세지 않았습니다 — ${offset + 251}건 이상`,
          },
        });
        page.artifacts[KIND].pagination.offset = offset;
        return jsonResponse(page);
      },
    });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(dataRows().length).toBeGreaterThan(0));
    // Page 0 + the prefetched page 1 are loaded: the bound is page 1's (251 + 250).
    await waitFor(() => expect(screen.getByTestId("grid-footer-total").textContent).toBe("총 501건 이상"));
    expect(screen.queryByTestId("r8-partial-banner")).toBeNull();
    expect(screen.getByTestId("grid-scope-badge").textContent).toContain("501건 이상");
    expect(document.body.textContent).not.toContain("미확정");
    expect(document.body.textContent).not.toContain(["전체", "미확인"].join(" "));
  });

  it("a scan that stopped at its cap with no match is not drawn as 'no rows'", async () => {
    openKind();
    installFetch({
      "/artifacts": () =>
        jsonResponse(
          kindPage({
            total: null,
            lowerBound: 0,
            truncated: true,
            scanned: 200_000,
            notice: { code: "TOTAL_NOT_COUNTED", message: "전체 건수는 세지 않았습니다 — 0건 이상" },
          }),
        ),
    });
    renderWithClient(<DataGrid />);
    const empty = await screen.findByTestId("grid-empty");
    expect(empty.textContent).toContain("일부만 확인했습니다(200,000행 확인)");
    expect(empty.textContent).not.toContain("표시할 행이 없습니다");
    expect(screen.queryByTestId("r8-partial-banner")).toBeNull();
  });

  it("a counted 0 under a filter reads '조건에 맞는 행이 없습니다 (전체 확인)'", async () => {
    openKind();
    installFetch({
      "/artifacts": () => jsonResponse(kindPage({ total: 0, lowerBound: 0, scanned: 40_024 })),
    });
    renderWithClient(<DataGrid />);
    const empty = await screen.findByTestId("grid-empty");
    expect(empty.textContent).toContain("조건에 맞는 행이 없습니다. (전체 확인)");
    expect(screen.queryByTestId("r8-partial-banner")).toBeNull();
    await waitFor(() => expect(screen.getByTestId("grid-footer-total").textContent).toBe("총 0건"));
  });

  it("an unfiltered empty node keeps its one honest sentence", async () => {
    openKind([]);
    installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            [KIND]: {
              artifacts: [],
              record_count: 0,
              pagination: {
                offset: 0,
                limit: 250,
                total: 0,
                total_lower_bound: 0,
                has_more: false,
                budget_stopped: false,
              },
            },
          },
        }),
    });
    renderWithClient(<DataGrid />);
    const empty = await screen.findByTestId("grid-empty");
    expect(empty.textContent).toContain("이 노드에는 표시할 행이 없습니다.");
  });
});

describe("footer count (T-020)", () => {
  it("exact, counting only while fetching, else a lower bound", () => {
    expect(footerTotalText(4770, false, 0)).toBe("총 4,770건");
    expect(footerTotalText(null, true, 250)).toBe("총 세는 중…");
    expect(footerTotalText(null, false, 1001)).toBe("총 1,001건 이상");
  });

  it("the footer falls back to the loaded rows when no bound was reported", () => {
    render(
      <GridFooter
        page={1}
        pageCount={null}
        total={null}
        shown={0}
        backend=""
        elapsedMs={0}
        truncated={false}
        filtering={false}
        sorting={false}
        loadedCount={250}
        canLoadMore={false}
        onLoadMore={() => {}}
        loading={false}
      />,
    );
    expect(screen.getByTestId("grid-footer-total").textContent).toBe("총 250건 이상");
  });
});
