// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
// Scroll perf split (IS-134): scrolling re-renders the rows only, and facts derived from the
// loaded rows are cached per page (a page load scans that page, not every loaded row again).
import { act, cleanup, fireEvent, renderHook, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CollectionQuery, GridRow } from "../../contracts/collection";
import { flaggedPagesSummary, flaggedRowsSummary } from "../flags/flags";
import { useGridLocalStore } from "./adapter";
import { DataGrid } from "./DataGrid";
import { emptyColumnIds, emptyColumnIdsOfPages } from "./gridUtils";
import {
  filesHandler,
  installFetch,
  mockLayout,
  queryWrapper,
  renderWithClient,
  resetGridStore,
} from "./testSupport";
import type { ColumnSpec } from "./types";
import { PAGE_SIZE, useCollectionQuery } from "./useCollectionQuery";

const toolbarRenders = vi.hoisted(() => ({ count: 0 }));
vi.mock("./GridToolbar", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./GridToolbar")>();
  return {
    ...actual,
    GridToolbar: (props: Parameters<typeof actual.GridToolbar>[0]) => {
      toolbarRenders.count += 1;
      return actual.GridToolbar(props);
    },
  };
});

let restoreLayout: () => void;
beforeEach(() => {
  resetGridStore();
  restoreLayout = mockLayout();
  toolbarRenders.count = 0;
});
afterEach(() => {
  cleanup();
  restoreLayout();
  vi.unstubAllGlobals();
});

const rows = () => screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index"));
const rowAt = (i: number) => rows().find((r) => r.getAttribute("data-index") === String(i));
const settle = () => act(() => new Promise((resolve) => setTimeout(resolve, 50)));

describe("GridBody split: scrolling re-renders the rows only", () => {
  it("a scroll moves the rendered rows and the footer page without re-rendering the toolbar", {
    timeout: 20_000,
  }, async () => {
    const calls = installFetch({ "/files": filesHandler(600) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rowAt(0)).toBeTruthy());
    await settle();
    const grid = screen.getByRole("grid");
    expect(screen.getByText("페이지 1/3")).toBeTruthy();
    const before = toolbarRenders.count;
    // Row 260 at the top: page 2 is requested, its rows render, the footer says 페이지 2/3.
    Object.defineProperty(grid, "scrollTop", { configurable: true, value: 260 * 28 });
    fireEvent.scroll(grid);
    await waitFor(() => expect(screen.getByText("페이지 2/3")).toBeTruthy());
    await waitFor(() => expect(calls.some((c) => c.url.includes("offset=250"))).toBe(true));
    // Scroll-only frames: the grid around the rows did not render again.
    const afterScroll = toolbarRenders.count;
    // (the page load that follows may re-render it once: compare against the scroll alone)
    Object.defineProperty(grid, "scrollTop", { configurable: true, value: 265 * 28 });
    fireEvent.scroll(grid);
    await waitFor(() => expect(rowAt(265 + 20)).toBeTruthy());
    Object.defineProperty(grid, "scrollTop", { configurable: true, value: 270 * 28 });
    fireEvent.scroll(grid);
    await waitFor(() => expect(rowAt(270 + 20)).toBeTruthy());
    await settle();
    expect(toolbarRenders.count - afterScroll).toBeLessThanOrEqual(1);
    expect(afterScroll).toBeGreaterThanOrEqual(before);
    // The focused row (0) stays mounted while scrolled away, and still the one tab stop.
    expect(rowAt(0)?.tabIndex).toBe(0);
    // aria-rowcount is the whole list (+ header), unaffected by the split.
    expect(grid.getAttribute("aria-rowcount")).toBe("601");
  });

  it("J/K, Space and the row menu still drive the rows rendered by GridBody", async () => {
    installFetch({ "/files": filesHandler(600) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rowAt(0)).toBeTruthy());
    const first = rowAt(0) as HTMLElement;
    first.focus();
    fireEvent.keyDown(first, { key: "j" });
    await waitFor(() => expect(rowAt(1)?.classList.contains("is-focused")).toBe(true));
    expect(document.activeElement).toBe(rowAt(1));
    fireEvent.keyDown(rowAt(1) as HTMLElement, { key: " " });
    await waitFor(() => expect(rowAt(1)?.getAttribute("aria-selected")).toBe("true"));
    expect([...useGridLocalStore.getState().selectedKeys]).toEqual(["files:/candidates/1"]);
    fireEvent.keyDown(rowAt(1) as HTMLElement, { key: "k" });
    await waitFor(() => expect(rowAt(0)?.classList.contains("is-focused")).toBe(true));
    const menuButton = within(rowAt(2) as HTMLElement).getByRole("button", { name: "행 메뉴" });
    fireEvent.click(menuButton);
    await waitFor(() => expect(menuButton.getAttribute("aria-expanded")).toBe("true"));
    expect(rowAt(2)?.classList.contains("is-focused")).toBe(true);
  });
});

describe("per-page derived data", () => {
  const row = (i: number, value: string): GridRow =>
    ({
      rowKey: `r:${i}`,
      title: `row ${i}`,
      tags: [],
      fields: { v: value },
    }) as unknown as GridRow;
  const column = (read: (row: GridRow) => unknown): ColumnSpec =>
    ({ id: "v", header: "V", width: 100, value: read }) as unknown as ColumnSpec;

  it("emptyColumnIdsOfPages scans a page once per column and matches emptyColumnIds", () => {
    const read = vi.fn((r: GridRow) => r.fields.v as string);
    const spec = column(read);
    const page0 = Array.from({ length: 50 }, (_, i) => row(i, ""));
    const page1 = Array.from({ length: 50 }, (_, i) => row(50 + i, ""));
    const options = { candidates: ["v"] };
    expect(emptyColumnIdsOfPages([spec], [page0], options)).toEqual(["v"]);
    const firstScan = read.mock.calls.length;
    expect(firstScan).toBeGreaterThanOrEqual(50);
    // A second page: only its rows are read; page 0 answers from the cache.
    expect(emptyColumnIdsOfPages([spec], [page0, page1], options)).toEqual(["v"]);
    expect(read.mock.calls.length - firstScan).toBeLessThanOrEqual(2 * 50);
    expect(read.mock.calls.slice(firstScan).every(([r]) => page1.includes(r))).toBe(true);
    // Same answers as the flat helper, with a value in the last page.
    const page2 = [row(100, "x")];
    expect(emptyColumnIdsOfPages([spec], [page0, page1, page2], options)).toEqual([]);
    expect(emptyColumnIds([spec], [...page0, ...page1, ...page2], options)).toEqual([]);
    expect(emptyColumnIdsOfPages([spec], [[], []], options)).toEqual([]);
  });

  it("flaggedPagesSummary equals flaggedRowsSummary over the same rows", () => {
    const flagged = (i: number, grade: string): GridRow =>
      ({ rowKey: `f:${i}`, tags: [], fields: { flagList: [{ id: `x${i}`, grade }] } }) as unknown as GridRow;
    const pages = [
      [flagged(1, "A"), row(2, "")],
      [row(3, ""), flagged(4, "C")],
    ];
    expect(flaggedPagesSummary(pages)).toEqual(flaggedRowsSummary(pages.flat()));
  });

  it("a page load keeps the earlier pages' arrays (and rows) as they were", async () => {
    installFetch({ "/files": filesHandler(2000) });
    const { wrapper } = queryWrapper();
    const query: CollectionQuery = { ref: { id: "files" }, offset: 0, limit: PAGE_SIZE };
    const { result } = renderHook(() => useCollectionQuery(query, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.loadedPages).toHaveLength(1));
    const page0 = result.current.loadedPages[0];
    act(() => result.current.ensureRange(0, 300));
    await waitFor(() => expect(result.current.loadedPages.length).toBeGreaterThanOrEqual(2));
    expect(result.current.loadedPages[0]).toBe(page0);
    expect(result.current.loadedRows).toHaveLength(
      result.current.loadedPages.reduce((n, page) => n + page.length, 0),
    );
    expect(result.current.loadedRows[0]).toBe(page0?.[0]);
  });
});
