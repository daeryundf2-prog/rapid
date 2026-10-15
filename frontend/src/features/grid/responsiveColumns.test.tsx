// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
    for (const name of ["이름", "경로", "크기", "수정", "NTFS 생성"]) expect(hasHeader(name)).toBe(true);
    // No loaded row carries a review mark: 선별 is held back like an empty 시각 (review #9).
    expect(hasHeader("선별")).toBe(false);
    const menu = openColumnMenu();
    expect(within(menu).queryByText(/폭 부족으로 숨김/)).toBeNull();
    const review = within(menu).getByTestId("grid-autohidden-review");
    expect(review.textContent).toContain("값이 없어 숨김 — 표시");
    fireEvent.click(within(review).getByRole("button", { name: "선별 표시 (값이 없어 숨김)" }));
    await waitFor(() => expect(hasHeader("선별")).toBe(true));
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
