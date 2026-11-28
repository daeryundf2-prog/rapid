// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetArtifactCountsCache } from "../../api/collections";
import { useAppStore } from "../../state/store";
import { useGridLocalStore } from "./adapter";
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

vi.mock("../../a11y", () => ({ announce: vi.fn() }));

/**
 * P1 (PR #36 review): the date/time columns are in view by default without a horizontal scroll.
 * Grid widths of the default layout (Layout.tsx): 1440px beside the open viewer ≈ 672px, 1440px
 * with the viewer rail ≈ 1076px, 1024px (viewer drawer, tree 28%) ≈ 700px.
 */
const WIDTHS = { "1440 + viewer": 672, "1440 rail": 1076, "1024 drawer": 700 } as const;
const SELECT_COL_WIDTH = 62;

let restoreLayout: () => void;
let restoreWidth: () => void;

/** The grid measures its scroll area through ResizeObserver + clientWidth (both absent in jsdom). */
function mockGridWidth(width: number): () => void {
  const proto = HTMLElement.prototype;
  const original = Object.getOwnPropertyDescriptor(proto, "clientWidth");
  Object.defineProperty(proto, "clientWidth", { configurable: true, get: () => width });
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

const headerCells = () => screen.getAllByRole("columnheader").filter((h) => h.dataset.col);
const headerIds = () => headerCells().map((h) => h.dataset.col);

/** Right edge of a column (select cell included) as laid out from the left of the grid. */
function rightEdge(id: string): number {
  let edge = SELECT_COL_WIDTH;
  for (const cell of headerCells()) {
    edge += Number.parseFloat(cell.style.width);
    if (cell.dataset.col === id) return edge;
  }
  throw new Error(`no header ${id}: ${headerIds().join(", ")}`);
}

const rows = () => screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index"));

/** Files rows with a 특이사항 flag: the widest default files layout. */
function flaggedFilesHandler(url: URL): Response {
  const limit = Number(url.searchParams.get("limit") ?? 0);
  const candidates = fileCandidates(0, Math.min(limit, 20)).map((c) => ({
    ...c,
    flags: [{ id: "eventlog.log_cleared", grade: "A", label: "로그 삭제" }],
  }));
  return jsonResponse({ candidates, total: 20, offset: 0, limit });
}

beforeEach(() => {
  resetGridStore();
  resetArtifactCountsCache();
  window.localStorage.clear();
  restoreLayout = mockLayout();
  restoreWidth = () => undefined;
});
afterEach(() => {
  cleanup();
  restoreLayout();
  restoreWidth();
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe("date/time columns in view by default (P1)", () => {
  it.each(Object.entries(WIDTHS))(
    "every artifact (mixed layout) at %s: 날짜 및 시각 leads",
    async (_, width) => {
      restoreWidth = mockGridWidth(width);
      useGridLocalStore.setState((s) => ({ route: { ...s.route, collection: { id: "artifacts" } } }));
      installFetch({ "/artifacts": sortedArtifactsHandler({ total: 30 }) });
      renderWithClient(<DataGrid />);
      await waitFor(() => expect(rows().length).toBeGreaterThan(0));
      await waitFor(() => expect(headerIds()[0]).toBe("sum:time"));
      expect(rightEdge("sum:time")).toBeLessThanOrEqual(width);
      // The cell carries the row's time (prefetch 마지막 실행), not an empty placeholder.
      const cell = rows()[0]?.querySelector('[data-col="sum:time"]');
      expect(cell?.textContent).toMatch(/2026-01-01/);
    },
  );

  it.each(Object.entries(WIDTHS))(
    "files with 특이사항 at %s: 수정 and NTFS 생성 follow 이름",
    async (_, width) => {
      restoreWidth = mockGridWidth(width);
      installFetch({ "/files": flaggedFilesHandler });
      renderWithClient(<DataGrid />);
      await waitFor(() => expect(rows().length).toBeGreaterThan(0));
      await waitFor(() => expect(headerIds()).toContain("flags"));
      expect(headerIds().slice(0, 3)).toEqual(["title", "flags", "timestamp"]);
      expect(rightEdge("timestamp")).toBeLessThanOrEqual(width);
      // NTFS 생성 is the lowest priority: a narrow grid hides it rather than scrolling 수정 away.
      if (headerIds().includes("ntfsCreated")) expect(rightEdge("ntfsCreated")).toBeLessThanOrEqual(width);
    },
  );

  it("a column the examiner hid stays hidden (the default order never overrides the 열 menu)", async () => {
    restoreWidth = mockGridWidth(WIDTHS["1440 rail"]);
    useGridLocalStore.setState((s) => ({ route: { ...s.route, collection: { id: "artifacts" } } }));
    installFetch({ "/artifacts": sortedArtifactsHandler({ total: 30 }) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(headerIds()[0]).toBe("sum:time"));
    fireEvent.click(screen.getByRole("button", { name: "열 설정" }));
    const menu = screen.getByRole("dialog", { name: "열 설정" });
    fireEvent.click(within(menu).getByRole("checkbox", { name: "날짜 및 시각" }));
    await waitFor(() => expect(headerIds()).not.toContain("sum:time"));
    expect(headerIds()[0]).toBe("type");
  });
});

describe("time columns name the display zone in the header, once (#79 follow-up)", () => {
  /** What the eye reads in a cell: its text without the visually hidden zone part. */
  const visibleText = (cell: Element | null | undefined) => {
    const copy = cell?.cloneNode(true) as Element | undefined;
    for (const hidden of copy?.querySelectorAll(".zone-time-hidden") ?? []) hidden.remove();
    return copy?.textContent ?? "";
  };
  const header = (id: string) => headerCells().find((h) => h.dataset.col === id)?.textContent;

  afterEach(() => useAppStore.setState({ timezone: null }));

  it("the header carries the zone and follows a zone change; cells show the time without it", async () => {
    restoreWidth = mockGridWidth(WIDTHS["1440 rail"]);
    useAppStore.setState({ timezone: "Asia/Seoul" });
    installFetch({ "/files": flaggedFilesHandler });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBeGreaterThan(0));
    expect(header("timestamp")).toBe("수정 (KST)");
    const cell = rows()[0]?.querySelector('[data-col="timestamp"]');
    expect(visibleText(cell)).toBe("2026-01-01 09:00:00");
    // A text selection, copy and screen readers still get the zone; so does the tooltip.
    expect(cell?.textContent).toBe("2026-01-01 09:00:00 KST");
    expect(cell?.getAttribute("title")).toContain("2026-01-01 09:00:00 KST");

    useAppStore.setState({ timezone: "utc" });
    await waitFor(() => expect(header("timestamp")).toBe("수정 (UTC)"));
    const utcCell = rows()[0]?.querySelector('[data-col="timestamp"]');
    expect(visibleText(utcCell)).toBe("2026-01-01 00:00:00");
    expect(utcCell?.textContent).toBe("2026-01-01 00:00:00 UTC");
  });
});
