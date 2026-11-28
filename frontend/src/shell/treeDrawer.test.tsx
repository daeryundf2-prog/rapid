import { QueryClient } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { caseCommands } from "../commands/builtin";
import { registerCommands, resetCommandRegistry, runCommand } from "../commands/registry";
import { TREE_DRAWER_KEY } from "../state/slices/overlays";
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

describe("Layout from 900px", () => {
  it("keeps the panel beside the page until the toggle folds it away", async () => {
    stubWindowWidth(1024);
    render(<Layout />);
    expect(screen.queryByTestId("tree-drawer")).toBeNull();
    expect(screen.getByTestId("tree-region")).toBeTruthy();
    const toggle = screen.getByTestId("tree-drawer-toggle");
    expect(toggle.getAttribute("aria-expanded")).toBe("true");

    expect(await runCommand("tree.panel")).toEqual({ ok: true });
    await waitFor(() => expect(screen.queryByTestId("tree-region")).toBeNull());
    expect(screen.getByTestId("tree-drawer-toggle").getAttribute("aria-expanded")).toBe("false");

    expect(await runCommand("tree.panel")).toEqual({ ok: true });
    await waitFor(() => expect(screen.getByTestId("tree-region")).toBeTruthy());
  });
});
