import { QueryClient } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { caseCommands, collapseViewerPane, expandViewerPane } from "../commands/builtin";
import { registerCommands, resetCommandRegistry, runCommand } from "../commands/registry";
import type { RowRef } from "../contracts/rowRef";
import { VIEWER_COLLAPSED_KEY, viewerPaneCollapsed } from "../state/slices/overlays";
import { resetAppStore, useAppStore } from "../state/store";
import { Layout } from "./Layout";

const ROW: RowRef = { collection: "files", locator: "/candidates/3" };
const collapsed = () => viewerPaneCollapsed(useAppStore.getState());

beforeAll(() => {
  // jsdom lacks ResizeObserver (react-resizable-panels).
  if (!("ResizeObserver" in window)) {
    class RO {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
    Object.assign(window, { ResizeObserver: RO });
    Object.assign(globalThis, { ResizeObserver: RO });
  }
});

beforeEach(() => {
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "/v2/");
  resetCommandRegistry();
  resetAppStore({ route: { runId: null, collection: null }, viewerPane: "auto" });
  useAppStore.getState().navigate({ runId: "r1", collection: "files" });
});

afterEach(() => {
  cleanup();
  resetCommandRegistry();
});

function selectRow() {
  useAppStore
    .getState()
    .setViewerTarget({ ref: ROW, runId: "r1", sourcePath: "C:\\x\\a.txt" }, { syncUrl: true });
}

describe("viewer pane collapse state", () => {
  it("collapses while no row is selected and follows the row selection (auto)", () => {
    expect(collapsed()).toBe(true);
    // The automatic first-row target (no `row=`) keeps the rail.
    useAppStore.getState().setViewerTarget({ ref: ROW, runId: "r1", sourcePath: null }, { syncUrl: false });
    expect(collapsed()).toBe(true);
    selectRow();
    expect(useAppStore.getState().route.row).toEqual(ROW);
    expect(collapsed()).toBe(false);
  });

  it("뷰어 접기 persists for the session and wins over a selected row; expand clears it", () => {
    selectRow();
    collapseViewerPane();
    expect(useAppStore.getState().viewerPane).toBe("collapsed");
    expect(window.sessionStorage.getItem(VIEWER_COLLAPSED_KEY)).toBe("1");
    expect(collapsed()).toBe(true);
    expandViewerPane();
    expect(useAppStore.getState().viewerPane).toBe("auto");
    expect(window.sessionStorage.getItem(VIEWER_COLLAPSED_KEY)).toBeNull();
    expect(collapsed()).toBe(false);
  });

  it("an explicit expand without a row keeps the pane open", () => {
    expandViewerPane();
    expect(useAppStore.getState().viewerPane).toBe("open");
    expect(collapsed()).toBe(false);
  });

  it("never collapses in the drawer layout", () => {
    useAppStore.getState().setViewerPane("collapsed");
    useAppStore.getState().setViewerIsDrawer(true);
    expect(collapsed()).toBe(false);
  });

  it("viewer.open expands the collapsed pane (wide) and opens the drawer (narrow)", async () => {
    registerCommands(caseCommands(new QueryClient()));
    selectRow();
    collapseViewerPane();
    expect(await runCommand("viewer.open")).toEqual({ ok: true });
    expect(collapsed()).toBe(false);

    collapseViewerPane();
    useAppStore.getState().setViewerIsDrawer(true);
    expect(await runCommand("viewer.open")).toEqual({ ok: true });
    expect(useAppStore.getState().viewerDrawerOpen).toBe(true);
    // The drawer leaves the wide layout's choice alone.
    expect(useAppStore.getState().viewerPane).toBe("collapsed");
  });
});

describe("Layout viewer rail", () => {
  it("shows the 36px rail without a row and the viewer once a row is selected", () => {
    render(<Layout />);
    const region = screen.getByTestId("viewer-region");
    expect(region.hasAttribute("data-collapsed")).toBe(true);
    expect(screen.getByRole("button", { name: "뷰어 펼치기" })).toBeTruthy();
    act(() => selectRow());
    expect(region.hasAttribute("data-collapsed")).toBe(false);
    expect(screen.queryByTestId("viewer-rail")).toBeNull();
  });

  it("the rail button expands the pane", () => {
    render(<Layout />);
    fireEvent.click(screen.getByRole("button", { name: "뷰어 펼치기" }));
    expect(useAppStore.getState().viewerPane).toBe("open");
    expect(screen.queryByTestId("viewer-rail")).toBeNull();
  });
});
