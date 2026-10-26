// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
import { QueryClient } from "@tanstack/react-query";
import { act, cleanup, configure, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetArtifactCountsCache } from "../../api/collections";
import { resetCommandRegistry } from "../../commands/registry";
import { EMPTY_ROUTE, parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import { registerAnalysisCommands } from "../analysis/commands";
import { useAnalysisStore } from "../analysis/store";
import { useGridLocalStore } from "./adapter";
import { COLUMN_FILTER_DEBOUNCE_MS } from "./ColumnFilterRow";
import { NTFS_EMPTY_HINT } from "./columns/files";
import { DataGrid } from "./DataGrid";
import {
  fileCandidates,
  installFetch,
  jsonResponse,
  mockLayout,
  renderWithClient,
  resetGridStore,
  sortedArtifactsHandler,
} from "./testSupport";

configure({ asyncUtilTimeout: 5000 });

const announceMock = vi.hoisted(() => vi.fn());
vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: announceMock,
}));

const RUN = "run-1";
let restoreLayout: () => void = () => undefined;
let offCommands: (() => void) | null = null;

function setRoute(hash: string) {
  window.location.hash = hash;
  useAppStore.getState().syncRouteFromLocation(parseHash(hash));
}

function gridOn(collection: { id: "files" | "artifacts" | "analysis"; kind?: string; analysisId?: string }) {
  useGridLocalStore.setState((s) => ({ route: { ...s.route, runId: RUN, collection, q: "", rowRef: null } }));
}

const dataRows = () => screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index"));
/** Opens the header's 열 설정 popover (visual-polish S3) unless it is open. */
const openColumnMenu = () => {
  const button = screen.getByRole("button", { name: "열 설정" });
  if (button.getAttribute("aria-expanded") !== "true") fireEvent.click(button);
};
/** Opens the 조건 panel (viewer-families U-F1: 열 구성 / 밀도 moved there). */
const openConditions = () => {
  const button = screen.getByRole("button", { name: /^조건/ });
  if (button.getAttribute("aria-expanded") !== "true") fireEvent.click(button);
};
const headerCell = (col: string) =>
  screen.getAllByRole("columnheader").find((h) => h.getAttribute("data-col") === col) as HTMLElement;

beforeEach(() => {
  resetCommandRegistry();
  resetGridStore();
  resetArtifactCountsCache();
  window.localStorage.clear();
  useAppStore.setState({ route: { ...EMPTY_ROUTE }, runs: [] });
  useAnalysisStore.setState({ runId: null, analyses: [], available: true, dialog: null });
  restoreLayout = mockLayout();
});
afterEach(() => {
  cleanup();
  offCommands?.();
  offCommands = null;
  restoreLayout();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  announceMock.mockReset();
  resetCommandRegistry();
  window.localStorage.clear();
});

function filesPage(total: number, ntfsJoin: unknown, withNtfs = false) {
  return (url: URL) => {
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? 250);
    const candidates = fileCandidates(offset, Math.min(offset + limit, total)).map((c, i) => ({
      ...c,
      ntfs:
        withNtfs && i === 0
          ? { entry_number: 4242, created_at: "2025-01-02T03:04:05Z", accessed_at: null }
          : null,
      filesystem: withNtfs && i === 0 ? "NTFS" : null,
      source_image: withNtfs ? "C:/rapid-qa/BSH.E01" : null,
    }));
    return jsonResponse({ candidates, total, offset, limit, ntfs_join: ntfsJoin });
  };
}

describe("files NTFS columns (plan analysis-workbench-p1 U-P1-3)", () => {
  it("before an NTFS-meta analysis the 출처 headers link to its run dialog; names stay clean", async () => {
    setRoute(`#/case/${RUN}/explore/files`);
    // Only an image input can run NTFS-meta (C-D12): the run is an E01.
    useAppStore.setState({
      runs: [{ run_id: RUN, status: "completed", request: { root: "D:/evidence/disk.E01" } }],
    } as never);
    gridOn({ id: "files" });
    installFetch({
      "/files": filesPage(3, { analysis_id: null, matched: 0, total: 3 }),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    offCommands = registerAnalysisCommands(new QueryClient());
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(dataRows()).toHaveLength(3));
    openConditions();
    fireEvent.change(screen.getByRole("combobox", { name: "열 구성" }), { target: { value: "source" } });
    for (const [col, name] of [
      ["ntfsCreated", "NTFS 생성"],
      ["ntfsAccessed", "NTFS 접근"],
      ["ntfsEntry", "MFT 엔트리"],
      ["filesystem", "파일 시스템"],
      ["sourceImage", "소스 이미지 경로"],
    ] as const) {
      const cell = headerCell(col);
      expect(cell.getAttribute("aria-label")).toBe(name);
      const sort = within(cell).getByRole("button", { name });
      expect(sort.getAttribute("title")).toBe(NTFS_EMPTY_HINT);
      const link = within(cell).getByRole("button", { name: "NTFS 메타 분석 실행…" });
      const described = (link.getAttribute("aria-describedby") ?? "")
        .split(" ")
        .map((id) => document.getElementById(id)?.textContent);
      expect(described).toContain(NTFS_EMPTY_HINT);
    }
    fireEvent.click(within(headerCell("ntfsEntry")).getByRole("button", { name: "NTFS 메타 분석 실행…" }));
    await waitFor(() => expect(useAnalysisStore.getState().dialog?.kind).toBe("ntfs-meta"));
    expect(screen.queryByTestId("grid-ntfs-status")).toBeNull();
  });

  it("after the join: cells filled, no links, and the match count in the status line", async () => {
    setRoute(`#/case/${RUN}/explore/files`);
    gridOn({ id: "files" });
    installFetch({ "/files": filesPage(3, { analysis_id: "ntfs-123456789", matched: 1, total: 3 }, true) });
    renderWithClient(<DataGrid initialPreset="source" />);
    await waitFor(() => expect(dataRows()).toHaveLength(3));
    openConditions();
    fireEvent.change(screen.getByRole("combobox", { name: "열 구성" }), { target: { value: "source" } });
    expect(screen.getByTestId("grid-ntfs-status").textContent).toBe(
      "NTFS 메타: 이 페이지 1/3행 일치 (분석 ntfs-123)",
    );
    expect(
      within(headerCell("ntfsEntry")).queryByRole("button", { name: "NTFS 메타 분석 실행…" }),
    ).toBeNull();
    const first = dataRows()[0] as HTMLElement;
    const cell = (col: string) => first.querySelector(`[data-col="${col}"]`)?.textContent;
    expect(cell("ntfsEntry")).toBe("4242");
    expect(cell("filesystem")).toBe("NTFS");
    expect(cell("sourceImage")).toBe("C:/rapid-qa/BSH.E01");
  });
});

describe("column header filters (plan analysis-workbench-p1 U-P1-4)", () => {
  it("toggle opens a filter row; a 크기 minimum filters loaded rows client-side and rides in cf=", async () => {
    setRoute(`#/case/${RUN}/explore/files`);
    gridOn({ id: "files" });
    installFetch({ "/files": filesPage(10, null) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(dataRows()).toHaveLength(10));
    // The column-filter row toggle lives in the header's 열 설정 menu (visual-polish S3).
    openColumnMenu();
    const toggle = screen.getByRole("button", { name: "열 필터 행" });
    expect(toggle.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-pressed")).toBe("true");
    fireEvent.keyDown(toggle, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "열 설정" })).toBeNull();
    const filterRow = screen.getByTestId("grid-colfilter-row");
    expect(filterRow.getAttribute("aria-rowindex")).toBe("2");
    // Data rows follow the header + filter rows.
    expect(dataRows()[0]?.getAttribute("aria-rowindex")).toBe("3");
    expect(within(filterRow).getByRole("textbox", { name: "수정 필터 (시작)" })).toBeTruthy();

    vi.useFakeTimers();
    const min = within(filterRow).getByRole("textbox", { name: "크기 필터 (최소)" });
    fireEvent.change(min, { target: { value: "1005" } });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(COLUMN_FILTER_DEBOUNCE_MS);
    });
    vi.useRealTimers();
    expect(useAppStore.getState().route.cf).toEqual([{ col: "size", op: ">", value: "1005" }]);
    // The browser percent-encodes ">" in the fragment; the router reads %3E back as the operator.
    expect(window.location.hash).toMatch(/cf=size(>|%3E)1005/);
    expect(parseHash(window.location.hash).cf).toEqual([{ col: "size", op: ">", value: "1005" }]);
    await waitFor(() => expect(dataRows()).toHaveLength(5));
    expect(screen.getByTestId("grid-colfilter-status").textContent).toBe("열 필터: 5건 / 불러온 10행 기준");
    openColumnMenu();
    expect(screen.getByRole("button", { name: "열 필터 행 (1)" })).toBeTruthy();
    fireEvent.keyDown(screen.getByRole("button", { name: "열 필터 행 (1)" }), { key: "Escape" });

    // Esc empties the input and drops the filter.
    fireEvent.keyDown(min, { key: "Escape" });
    await waitFor(() => expect(useAppStore.getState().route.cf).toBeUndefined());
    await waitFor(() => expect(dataRows()).toHaveLength(10));
    expect(screen.queryByTestId("grid-colfilter-status")).toBeNull();
  });

  it("a cf= deep link opens the row and restores each input", async () => {
    setRoute(`#/case/${RUN}/explore/files?cf=title:file-1,timestamp:2026-01-01..`);
    gridOn({ id: "files" });
    installFetch({ "/files": filesPage(12, null) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(dataRows()).toHaveLength(3)); // file-1, file-10, file-11
    const row = screen.getByTestId("grid-colfilter-row");
    expect((within(row).getByRole("textbox", { name: "이름 필터" }) as HTMLInputElement).value).toBe(
      "file-1",
    );
    expect((within(row).getByRole("textbox", { name: "수정 필터 (시작)" }) as HTMLInputElement).value).toBe(
      "2026-01-01",
    );
    expect((within(row).getByRole("textbox", { name: "수정 필터 (끝)" }) as HTMLInputElement).value).toBe("");
  });

  it("artifacts: 경로 → path_contains and 유형 → artifact_type on the request; server count in the status line", async () => {
    setRoute(`#/case/${RUN}/explore/artifacts/windows-prefetch?cf=path:APP1,type:prefetch-file`);
    gridOn({ id: "artifacts", kind: "windows-prefetch" });
    const calls = installFetch({ "/artifacts": sortedArtifactsHandler({ total: 5 }) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(dataRows().length).toBeGreaterThan(0));
    const request = calls.find((c) => c.url.includes("/artifacts?")) as { url: string };
    const params = new URL(request.url, "http://x").searchParams;
    expect(params.get("path_contains")).toBe("APP1");
    expect(params.getAll("artifact_type")).toEqual(["prefetch-file"]);
    // Server-side column filters: the server count, never "불러온 m행 기준".
    expect(screen.getByTestId("grid-colfilter-status").textContent).toBe("열 필터: 5건 (서버 필터)");
  });

  it("the web log node's types= go to the server as repeated artifact_type and show as a 유형 chip", async () => {
    setRoute(`#/case/${RUN}/explore/artifacts/windows-system?types=web-server-log,webshell-source-candidate`);
    gridOn({ id: "artifacts", kind: "windows-system" });
    const calls = installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            "windows-system": {
              artifacts: [
                {
                  artifact_type: "web-server-log",
                  path: "C:/inetpub/logs/u_ex1.log",
                  details: {},
                  record_index: 0,
                },
                {
                  artifact_type: "webshell-source-candidate",
                  path: "C:/inetpub/wwwroot/a.aspx",
                  details: {},
                  record_index: 4,
                },
              ],
              total: 2,
            },
          },
        }),
    });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(dataRows()).toHaveLength(2));
    // (The grid also reads /tree for the 유형 options; pick the artifacts page request.)
    const page = calls.find((c) => c.url.includes("/artifacts")) as { url: string };
    const params = new URL(page.url, "http://x").searchParams;
    expect(params.getAll("kind")).toEqual(["windows-system"]);
    expect(params.getAll("artifact_type")).toEqual(["web-server-log", "webshell-source-candidate"]);
    const typeCell = (dataRows()[0] as HTMLElement).querySelector('[data-col="type"] .grid-type-text');
    // The chip reads the Korean type name; the exact artifact_type stays on the element / tooltip.
    expect(typeCell?.textContent).toBe("웹 서버 로그");
    expect(typeCell?.getAttribute("data-type")).toBe("web-server-log");
    expect(screen.getByRole("button", { name: "유형 web-server-log 조건 제거" })).toBeTruthy();
  });

  it("analysis rows: 경로 column filter → path_contains on the rows request", async () => {
    setRoute(`#/case/${RUN}/explore/analysis/carve?id=c1&cf=path:blob`);
    gridOn({ id: "analysis", kind: "carve", analysisId: "c1" });
    const calls = installFetch({
      "/rows": () =>
        jsonResponse({
          rows: [
            { artifact_type: "carve-row", path: "C:/e/blob.bin", record_index: 3, details: { offset: 16 } },
          ],
          record_count: 9,
          pagination: { filtered: true, has_more: false },
        }),
    });
    renderWithClient(<DataGrid collection={{ id: "analysis", kind: "carve", analysisId: "c1" }} />);
    await waitFor(() => expect(dataRows()).toHaveLength(1));
    const request = calls.find((c) => c.url.includes("/rows")) as { url: string };
    expect(request.url).toContain(`/api/runs/${RUN}/analyses/c1/rows?`);
    expect(new URL(request.url, "http://x").searchParams.get("path_contains")).toBe("blob");
    expect(dataRows()[0]?.getAttribute("data-row-key")).toBe("analysis:c1:/rows/3");
  });
});

describe("result announcements (review item 8)", () => {
  it("a background refetch that only changes the count (job polling) stays silent", async () => {
    setRoute(`#/case/${RUN}/explore/analysis/carve?id=c1`);
    gridOn({ id: "analysis", kind: "carve", analysisId: "c1" });
    let count = 1;
    installFetch({
      "/rows": () =>
        jsonResponse({
          rows: Array.from({ length: count }, (_, i) => ({
            artifact_type: "carve-row",
            path: `C:/e/${i}.bin`,
            record_index: i,
            details: { offset: i },
          })),
          record_count: count,
        }),
    });
    const { client } = renderWithClient(
      <DataGrid collection={{ id: "analysis", kind: "carve", analysisId: "c1" }} />,
    );
    await waitFor(() => expect(dataRows()).toHaveLength(1));
    await waitFor(() =>
      expect(announceMock.mock.calls.filter(([t]) => /건 ·/.test(String(t)))).toHaveLength(1),
    );
    count = 3;
    await act(async () => {
      await client.invalidateQueries({ queryKey: ["collection", RUN, "analysis"] });
    });
    await waitFor(() => expect(dataRows()).toHaveLength(3));
    expect(announceMock.mock.calls.filter(([t]) => /건 ·/.test(String(t)))).toHaveLength(1);
  });
});
