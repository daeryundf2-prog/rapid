// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetArtifactCountsCache } from "../../api/collections";
import { useAppStore } from "../../state/store";
import { FALLBACK_CATALOG, setCatalog } from "../flags/catalog";
import { flaggedRowsSummary, flagsColumnSparse, flagsHeaderHint } from "../flags/flags";
import { useGridLocalStore } from "./adapter";
import { DataGrid } from "./DataGrid";
import {
  fileCandidates,
  filesHandler,
  installFetch,
  jsonResponse,
  mockLayout,
  renderWithClient,
  resetGridStore,
} from "./testSupport";

vi.mock("../../a11y", () => ({ announce: vi.fn() }));

let restoreLayout: () => void;
let restoreWidth: () => void;

/** The grid measures its scroll area through ResizeObserver + clientWidth (both absent in jsdom). */
function mockGridWidth(width: number): () => void {
  const proto = HTMLElement.prototype;
  const original = Object.getOwnPropertyDescriptor(proto, "clientWidth");
  Object.defineProperty(proto, "clientWidth", { configurable: true, get: () => width });
  // The grid measures clientWidth once on mount; observers never fire here.
  class RO {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  vi.stubGlobal("ResizeObserver", RO);
  return () => {
    if (original) Object.defineProperty(proto, "clientWidth", original);
    else delete (proto as unknown as Record<string, unknown>).clientWidth;
  };
}

const headers = () => screen.getAllByRole("columnheader").map((h) => h.textContent ?? "");
const hasHeader = (name: string) => headers().some((text) => text.includes(name));

async function renderFiles(handler = filesHandler(20)) {
  installFetch({ "/files": handler });
  renderWithClient(<DataGrid />);
  await waitFor(() => expect(screen.getAllByRole("row").length).toBeGreaterThan(2));
}

function openColumnMenu() {
  fireEvent.click(screen.getByRole("button", { name: "열 설정" }));
  return screen.getByRole("dialog", { name: "열 설정" });
}

beforeEach(() => {
  resetGridStore();
  window.localStorage.removeItem("rapidtriage.grid.preset");
  restoreLayout = mockLayout();
  restoreWidth = () => undefined;
});
afterEach(() => {
  cleanup();
  restoreLayout();
  restoreWidth();
  vi.unstubAllGlobals();
});

describe("responsive default columns (files, 분석 기본)", () => {
  it("hides the lowest-priority columns on a narrow grid and lists them in the 열 menu", async () => {
    // 600 − select 56 − tools 40 = 504px: NTFS 생성, 경로 and 선별 go; 이름 · 수정 · 크기 stay.
    restoreWidth = mockGridWidth(600);
    await renderFiles();
    await waitFor(() => expect(hasHeader("경로")).toBe(false));
    expect(hasHeader("이름")).toBe(true);
    expect(hasHeader("수정")).toBe(true);
    expect(hasHeader("크기")).toBe(true);
    expect(hasHeader("선별")).toBe(false);
    expect(hasHeader("NTFS 생성")).toBe(false);

    const menu = openColumnMenu();
    const pathRow = within(menu).getByTestId("grid-autohidden-path");
    expect(pathRow.textContent).toContain("폭 부족으로 숨김 — 표시");
    expect((within(pathRow).getByRole("checkbox") as HTMLInputElement).checked).toBe(false);
    expect(within(menu).queryByTestId("grid-autohidden-title")).toBeNull();

    // Showing 경로 pins it: lower-priority columns make room for it instead.
    fireEvent.click(within(menu).getByRole("button", { name: "경로 표시 (폭 부족으로 숨김)" }));
    await waitFor(() => expect(hasHeader("경로")).toBe(true));
    expect(within(menu).queryByTestId("grid-autohidden-path")).toBeNull();
    expect(within(menu).getByTestId("grid-autohidden-size")).toBeTruthy();
    expect(hasHeader("크기")).toBe(false);
  });

  it("shows every default column with values when the grid is wide enough", async () => {
    restoreWidth = mockGridWidth(1200);
    await renderFiles();
    for (const name of ["이름", "경로", "크기", "수정"]) expect(hasHeader(name)).toBe(true);
    // A folder input has no NTFS-meta to run (C-D12): its empty NTFS 생성 hides like any empty column.
    expect(hasHeader("NTFS 생성")).toBe(false);
    // No loaded row carries a review mark: 검토 is held back like an empty 시각 (review #9).
    expect(hasHeader("검토")).toBe(false);
    const menu = openColumnMenu();
    expect(within(menu).queryByText(/폭 부족으로 숨김/)).toBeNull();
    expect(within(menu).getByTestId("grid-autohidden-ntfsCreated").textContent).toContain("값이 없어 숨김");
    expect(document.querySelector(".grid-hint-link")).toBeNull();
    const review = within(menu).getByTestId("grid-autohidden-review");
    expect(review.textContent).toContain("값이 없어 숨김 — 표시");
    fireEvent.click(within(review).getByRole("button", { name: "검토 표시 (값이 없어 숨김)" }));
    await waitFor(() => expect(hasHeader("검토")).toBe(true));
  });

  it("an image input keeps NTFS 생성 with its 실행 hint; a folder input gets no link (C-D12)", async () => {
    restoreWidth = mockGridWidth(1400);
    const app = useAppStore.getState();
    useAppStore.setState({
      route: { ...app.route, runId: "run-1" },
      runs: [{ run_id: "run-1", status: "completed", request: { root: "D:/evidence/disk.E01" } }],
    } as never);
    try {
      await renderFiles();
      await waitFor(() => expect(hasHeader("NTFS 생성")).toBe(true));
      const ntfs = screen
        .getAllByRole("columnheader")
        .find((h) => h.getAttribute("data-col") === "ntfsCreated") as HTMLElement;
      expect(ntfs.querySelector(".grid-hint-link")?.textContent).toContain("실행");
    } finally {
      useAppStore.setState({ route: app.route, runs: app.runs } as never);
    }
  });

  it("a widened grid gives the spare width to 이름 and 경로, not to the time / size columns (C-D7)", async () => {
    restoreWidth = mockGridWidth(1600);
    await renderFiles();
    const width = (id: string) =>
      Number.parseFloat(
        (screen.getAllByRole("columnheader").find((h) => h.getAttribute("data-col") === id) as HTMLElement)
          .style.width,
      );
    expect(width("title")).toBeGreaterThan(220);
    expect(width("path")).toBeGreaterThan(200);
    expect(width("timestamp")).toBe(180);
    expect(width("size")).toBe(80);
    // Every column together fills the pane exactly: no sideways scroll.
    const total = ["title", "path", "size", "timestamp"].reduce((sum, id) => sum + width(id), 0);
    expect(total).toBe(1600 - 56);
  });

  it("a sorted column is never the one hidden for width (C-D2)", async () => {
    restoreWidth = mockGridWidth(600);
    await renderFiles();
    await waitFor(() => expect(hasHeader("경로")).toBe(false));
    // Sort by 크기 (kept); then narrow priorities never drop it.
    const size = screen
      .getAllByRole("columnheader")
      .find((h) => h.getAttribute("data-col") === "size") as HTMLElement;
    fireEvent.click(within(size).getByRole("button"));
    await waitFor(() => expect(size.getAttribute("aria-sort")).toBe("ascending"));
    expect(hasHeader("크기")).toBe(true);
  });

  it("hides 수정 when no loaded row has a time, with the same 열 menu hint", async () => {
    restoreWidth = mockGridWidth(1200);
    await renderFiles((url) => {
      const limit = Number(url.searchParams.get("limit") ?? 0);
      const candidates = fileCandidates(0, Math.min(limit, 20)).map(
        ({ modified_at: _drop, ...rest }) => rest,
      );
      return jsonResponse({ candidates, total: 20, offset: 0, limit });
    });
    await waitFor(() => expect(hasHeader("수정")).toBe(false));
    const menu = openColumnMenu();
    const row = within(menu).getByTestId("grid-autohidden-timestamp");
    expect(row.textContent).toContain("값이 없어 숨김 — 표시");
    fireEvent.click(within(row).getByRole("checkbox"));
    await waitFor(() => expect(hasHeader("수정")).toBe(true));
  });

  it("leaves non-default presets alone", async () => {
    window.localStorage.setItem("rapidtriage.grid.preset", "source");
    restoreWidth = mockGridWidth(600);
    await renderFiles();
    expect(hasHeader("경로")).toBe(true);
    const menu = openColumnMenu();
    expect(within(menu).queryByText(/숨김 — 표시/)).toBeNull();
    window.localStorage.removeItem("rapidtriage.grid.preset");
  });
});

describe("browser kind layout fits the pane (r7 S1, real-data 1920 overflow 43px)", () => {
  // The real catalogue (not the test mock): the browser kind is the browser-history family —
  // 마지막 방문 · 항목 · 특이사항 · 제목 · URL · 방문 수 · 브라우저 · 프로필 · 유형. Its default widths
  // (1576 with the select column) exceed the 1533px pane of a 1920 window; the priority hiding
  // counts minimums, so nothing hid and the grid scrolled sideways.
  function browserRows() {
    return Array.from({ length: 20 }, (_, i) => ({
      artifact_type: "browser-history",
      path: "C:/Users/a/AppData/Local/Google/Chrome/User Data/Default/History",
      details: {
        timestamp: "2026-01-01T00:00:00Z",
        title: `Page ${i}`,
        url: `https://example.com/path/${i}?q=${i}`,
        visit_count: i,
        typed_count: 0,
        browser: "Chrome",
        profile: "Default",
      },
      record_index: i,
      ...(i % 3 === 0 ? { flags: [{ id: "probe", grade: "B", label: "검토" }] } : {}),
    }));
  }
  const widthOf = (id: string) =>
    Number.parseFloat(
      (
        screen.getAllByRole("columnheader").find((h) => h.getAttribute("data-col") === id) as
          | HTMLElement
          | undefined
      )?.style.width ?? "0",
    );

  beforeEach(() => {
    resetArtifactCountsCache();
    setCatalog(FALLBACK_CATALOG, "server");
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, collection: { id: "artifacts", kind: "browser" }, q: "", rowRef: null },
    }));
  });
  afterEach(() => setCatalog(null));

  // 1533 = the grid pane of a 1920 window (measured); 1213 = a 1600 window with the tree open.
  for (const pane of [1533, 1213]) {
    it(`fills a ${pane}px pane exactly with URL and 제목 readable`, async () => {
      restoreWidth = mockGridWidth(pane);
      installFetch({
        "/artifacts": () => jsonResponse({ artifacts: { browser: { artifacts: browserRows(), total: 20 } } }),
      });
      renderWithClient(<DataGrid />);
      await waitFor(() => expect(widthOf("d:url")).toBeGreaterThan(0));
      await waitFor(() => expect(widthOf("flags")).toBeGreaterThan(0));
      const total = screen
        .getAllByRole("columnheader")
        .reduce((sum, h) => sum + (Number.parseFloat(h.style.width) || 0), 0);
      expect(total).toBe(pane);
      // URL / 제목 / 항목 keep their default width: the fixed-width columns gave the room first.
      expect(widthOf("d:url")).toBeGreaterThanOrEqual(240);
      expect(widthOf("d:title")).toBeGreaterThanOrEqual(150);
      expect(widthOf("title")).toBeGreaterThanOrEqual(240);
      // A time cell never loses its seconds.
      expect(widthOf("d:timestamp")).toBeGreaterThanOrEqual(180);
    });
  }

  // R-11 (real data: one flagged row among 500 loaded): the column stays (a row has a flag) but is
  // narrow, and its header says how many loaded rows carry a flag and that a click sorts them up.
  it("a sparse 특이사항 column keeps its 90px minimum and names the flagged rows in its header", async () => {
    restoreWidth = mockGridWidth(1533);
    const rows = browserRows().map((row, i) => {
      const { flags: _flags, ...rest } = row as typeof row & { flags?: unknown };
      return i === 4 ? { ...rest, flags: [{ id: "probe", grade: "B", label: "검토" }] } : rest;
    });
    installFetch({
      "/artifacts": () => jsonResponse({ artifacts: { browser: { artifacts: rows, total: 20 } } }),
    });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(widthOf("flags")).toBeGreaterThan(0));
    expect(widthOf("flags")).toBe(90);
    const header = screen.getAllByRole("columnheader").find((h) => h.getAttribute("data-col") === "flags");
    const sort = within(header as HTMLElement).getByRole("button", { name: /특이사항/ });
    expect(sort.getAttribute("data-flag-hint")).toBe("특이사항 1건 (B)");
    expect(sort.getAttribute("title")).toBe("특이사항 1건 (B) · 불러온 20행 중 — 눌러 등급순 정렬");
    expect(sort.getAttribute("aria-describedby")).toMatch(/flagged-flags/);
  });

  it("a 특이사항 column with many flagged rows keeps its default width", async () => {
    restoreWidth = mockGridWidth(1533);
    installFetch({
      "/artifacts": () => jsonResponse({ artifacts: { browser: { artifacts: browserRows(), total: 20 } } }),
    });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(widthOf("flags")).toBeGreaterThan(0));
    expect(widthOf("flags")).toBeGreaterThan(90);
    const header = screen.getAllByRole("columnheader").find((h) => h.getAttribute("data-col") === "flags");
    expect(
      within(header as HTMLElement)
        .getByRole("button")
        .getAttribute("data-flag-hint"),
    ).toBe("특이사항 7건 (B)");
  });
});

describe("flagged rows summary (R-11)", () => {
  const flagged = (grade: string) => ({ fields: { flags: [{ id: "x", grade, label: "x" }] } });
  const plain = { fields: {} };
  it("counts flagged rows, lists their top grades A→C, and calls one in ten sparse", () => {
    const summary = flaggedRowsSummary([flagged("C"), plain, flagged("A"), plain]);
    expect(summary).toEqual({ count: 2, loaded: 4, grades: ["A", "C"] });
    expect(flagsHeaderHint(summary)).toBe("특이사항 2건 (A·C)");
    expect(flagsColumnSparse(summary)).toBe(false);
    const sparse = flaggedRowsSummary([flagged("B"), ...Array.from({ length: 499 }, () => plain)]);
    expect(flagsHeaderHint(sparse)).toBe("특이사항 1건 (B)");
    expect(flagsColumnSparse(sparse)).toBe(true);
    expect(flagsHeaderHint(flaggedRowsSummary([plain]))).toBe("");
    expect(flagsColumnSparse(flaggedRowsSummary([plain]))).toBe(false);
  });
});
