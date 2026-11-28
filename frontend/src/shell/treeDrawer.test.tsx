import { QueryClient } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { caseCommands } from "../commands/builtin";
import { registerCommands, resetCommandRegistry, runCommand } from "../commands/registry";
import { TREE_DRAWER_KEY } from "../state/slices/overlays";
import { treePanelHidden, treePanelKind } from "../state/slices/prefs";
import { resetAppStore, useAppStore } from "../state/store";
import { Layout } from "./Layout";

const s = () => useAppStore.getState();
let frames: FrameRequestCallback[] = [];
/** Run the focus moves the commands queued for the next frame. */
const flushFrames = () => {
  for (const frame of frames.splice(0)) frame(0);
};

/** A window `width` px wide for the layout's max-width queries. */
function stubWindowWidth(width: number) {
  vi.stubGlobal("matchMedia", (query: string) => {
    const max = /max-width:\s*([\d.]+)px/.exec(query);
    return {
      matches: max ? width <= Number(max[1]) : false,
      addEventListener() {},
      removeEventListener() {},
    };
  });
}

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
  window.localStorage.clear();
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "/v2/");
  frames = [];
  vi.stubGlobal("requestAnimationFrame", (frame: FrameRequestCallback) => frames.push(frame));
  resetCommandRegistry();
  registerCommands(caseCommands(new QueryClient()));
  resetAppStore({ route: { runId: null, collection: null } });
  s().navigate({ runId: "r1", collection: "artifacts" });
});

afterEach(() => {
  cleanup();
  resetCommandRegistry();
  vi.unstubAllGlobals();
});

describe("tree drawer state", () => {
  it("remembers the open state and restores it when the narrow layout is entered", () => {
    s().setTreeIsDrawer(true);
    expect(s().treeDrawerOpen).toBe(false);
    s().setOverlay("treeDrawer", true);
    expect(window.localStorage.getItem(TREE_DRAWER_KEY)).toBe("1");
    // Wide again: no drawer to show, the choice stays stored.
    s().setTreeIsDrawer(false);
    expect(s().treeDrawerOpen).toBe(false);
    s().setTreeIsDrawer(true);
    expect(s().treeDrawerOpen).toBe(true);
    s().setOverlay("treeDrawer", false);
    expect(window.localStorage.getItem(TREE_DRAWER_KEY)).toBeNull();
  });

  it("never shows the tree drawer and the viewer drawer together", () => {
    s().setTreeIsDrawer(true);
    s().setViewerIsDrawer(true);
    s().setOverlay("treeDrawer", true);
    s().setOverlay("viewerDrawer", true);
    expect(s().treeDrawerOpen).toBe(false);
    expect(window.localStorage.getItem(TREE_DRAWER_KEY)).toBeNull();
    s().setOverlay("treeDrawer", true);
    expect(s().viewerDrawerOpen).toBe(false);
  });
});

describe("Layout below 900px", () => {
  it("gives the page the whole width and opens the panel from the stage rail", async () => {
    stubWindowWidth(500);
    render(<Layout />);
    const drawer = screen.getByTestId("tree-drawer");
    const toggle = screen.getByTestId("tree-drawer-toggle");
    expect(screen.getByTestId("workbench-shell").dataset.tree).toBe("drawer");
    expect(drawer.hidden).toBe(true);
    expect(drawer.contains(screen.getByTestId("tree-region"))).toBe(true);
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(toggle.getAttribute("aria-controls")).toBe(drawer.id);

    await act(async () => {
      fireEvent.click(toggle);
    });
    act(flushFrames);
    expect(drawer.hidden).toBe(false);
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(document.activeElement).toBe(drawer.querySelector("h1"));

    // Esc closes it and hands focus back to the toggle.
    fireEvent.keyDown(document, { key: "Escape" });
    expect(drawer.hidden).toBe(true);
    expect(document.activeElement).toBe(toggle);
  });

  it("closes on a destination picked inside it, not on a stage switch", () => {
    stubWindowWidth(720);
    render(<Layout />);
    const focusHeading = () => (screen.getByTestId("tree-drawer").querySelector("h1") as HTMLElement).focus();
    act(() => s().setOverlay("treeDrawer", true));
    focusHeading();
    act(() => s().navigate({ runId: "r1", collection: "timeline" }));
    expect(s().treeDrawerOpen).toBe(false);

    act(() => s().setOverlay("treeDrawer", true));
    focusHeading();
    act(() => s().navigate({ runId: "r1", collection: "intake" }));
    expect(s().treeDrawerOpen).toBe(true);
  });

  it("keeps a navigation made elsewhere from closing it", () => {
    stubWindowWidth(720);
    render(<Layout />);
    act(() => s().setOverlay("treeDrawer", true));
    screen.getByTestId("tree-drawer-toggle").focus();
    act(() => s().navigate({ runId: "r1", collection: "timeline" }));
    expect(s().treeDrawerOpen).toBe(true);
  });
});

describe("Layout from 900px: the foldable panel (F24)", () => {
  const region = () => screen.getByTestId("tree-region");

  it("keeps the panel beside a browsing view; Alt+0's command folds it to the strip and back", async () => {
    stubWindowWidth(1024);
    render(<Layout />);
    expect(screen.queryByTestId("tree-drawer")).toBeNull();
    expect(screen.queryByTestId("tree-drawer-toggle")).toBeNull();
    expect(region().hidden).toBe(false);
    expect(screen.queryByTestId("tree-strip")).toBeNull();

    await act(async () => {
      expect(await runCommand("tree.panel")).toEqual({ ok: true });
    });
    act(flushFrames);
    expect(region().hidden).toBe(true);
    const expand = screen.getByRole("button", { name: "탐색 트리 펼치기" });
    expect(expand.getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).toBe(expand);
    expect(JSON.parse(window.localStorage.getItem("rapidtriage.v2.treePanel") ?? "{}")).toEqual({
      browse: "hidden",
    });

    // The strip's button brings it back; focus lands on the panel heading.
    await act(async () => {
      fireEvent.click(expand);
    });
    act(flushFrames);
    expect(region().hidden).toBe(false);
    expect(document.activeElement).toBe(region().querySelector("h1"));
  });

  it("starts folded on timeline and search, open on the review board; each kind keeps its own pin", async () => {
    stubWindowWidth(1280);
    render(<Layout />);
    act(() => s().navigate({ runId: "r1", collection: "timeline" }));
    expect(region().hidden).toBe(true);
    // No tree mounted in this test: the strip names the view.
    expect(screen.getByTestId("tree-strip").textContent).toContain("타임라인");

    // The heading's 접기 / the strip's 펼치기 pin the timeline kind open.
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "탐색 트리 펼치기" }));
    });
    expect(region().hidden).toBe(false);
    act(() => s().navigate({ runId: "r1", collection: "search", q: "x" }));
    expect(region().hidden).toBe(true);
    act(() => s().navigate({ runId: "r1", collection: "files" }));
    expect(region().hidden).toBe(false);
    act(() => s().navigate({ runId: "r1", collection: "review" }));
    expect(region().hidden).toBe(false);
    act(() => s().navigate({ runId: "r1", collection: "timeline" }));
    expect(region().hidden).toBe(false);

    await act(async () => {
      fireEvent.click(screen.getByTestId("tree-collapse"));
    });
    expect(region().hidden).toBe(true);
    expect(JSON.parse(window.localStorage.getItem("rapidtriage.v2.treePanel") ?? "{}")).toEqual({
      timeline: "hidden",
    });
  });
});

describe("Layout below 600px: list ↔ detail (F23)", () => {
  const target = { runId: "r1", collection: "files", rowKey: "k1", ref: { kind: "file", id: "1" } };

  function addRow(): HTMLElement {
    const main = document.getElementById("main") as HTMLElement;
    const row = document.createElement("div");
    row.setAttribute("role", "row");
    row.dataset.index = "0";
    row.innerHTML =
      '<div class="grid-cell grid-cell-select"><input type="checkbox" aria-label="선택"></div><span class="text">보고서.docx</span>';
    main.appendChild(row);
    return row;
  }

  it("a tap on the row text opens the full-width detail; 목록으로 closes it, checkbox taps stay in the list", async () => {
    stubWindowWidth(390);
    render(<Layout />);
    act(() => {
      useAppStore.setState({ viewerTarget: target as never });
    });
    // The 뷰어 열기 bar sits under the list (no floating button over the rows).
    expect(screen.getByTestId("viewer-drawer-open").closest(".drawer-handle")).toBeTruthy();
    const row = addRow();

    await act(async () => {
      fireEvent.click(row.querySelector("input") as HTMLElement);
    });
    expect(s().viewerDrawerOpen).toBe(false);

    await act(async () => {
      fireEvent.click(row.querySelector(".text") as HTMLElement);
    });
    expect(s().viewerDrawerOpen).toBe(true);
    const back = screen.getByTestId("viewer-drawer-back");
    expect(back.textContent).toContain("목록으로");
    fireEvent.click(back);
    expect(s().viewerDrawerOpen).toBe(false);
  });

  it("from 600px a row tap keeps the side drawer closed (keyboard J/K browsing stays in the list)", async () => {
    stubWindowWidth(1024);
    render(<Layout />);
    act(() => {
      useAppStore.setState({ viewerTarget: target as never });
    });
    const row = addRow();
    await act(async () => {
      fireEvent.click(row.querySelector(".text") as HTMLElement);
    });
    expect(s().viewerDrawerOpen).toBe(false);
    expect(screen.queryByTestId("viewer-drawer-back")).toBeNull();
  });
});

describe("treePanelHidden (F24)", () => {
  const state = (collection: string | null, treeIsDrawer = false, treePanelPins = {}) => ({
    route: { collection },
    treeIsDrawer,
    treePanelPins,
  });

  it("folds the event lists by default, keeps browsing views open, honours pins, never in the drawer", () => {
    expect(treePanelKind("timeline")).toBe("timeline");
    expect(treePanelKind("artifacts")).toBe("browse");
    expect(treePanelHidden(state("timeline"))).toBe(true);
    expect(treePanelHidden(state("search"))).toBe(true);
    expect(treePanelHidden(state("review"))).toBe(false);
    expect(treePanelHidden(state("review", false, { review: "hidden" }))).toBe(true);
    expect(treePanelHidden(state("files"))).toBe(false);
    expect(treePanelHidden(state("intake"))).toBe(false);
    expect(treePanelHidden(state("timeline", false, { timeline: "shown" }))).toBe(false);
    expect(treePanelHidden(state("files", false, { browse: "hidden" }))).toBe(true);
    expect(treePanelHidden(state("timeline", true))).toBe(false);
  });
});
