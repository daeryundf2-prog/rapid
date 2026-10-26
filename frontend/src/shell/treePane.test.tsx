import { QueryClient } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { caseCommands, MAIN_ID, TREE_EXPAND_ID, toggleTreePane } from "../commands/builtin";
import { registerCommands, resetCommandRegistry, runCommand } from "../commands/registry";
import { useViewPrefs } from "../features/review/viewPrefs";
import { StageRail } from "../features/stages/StageRail";
import { STAGE_HEADING_ID } from "../features/stages/stages";
import { storedTreeCollapsed, TREE_COLLAPSED_KEY } from "../state/slices/overlays";
import { resetAppStore, useAppStore } from "../state/store";
import {
  Layout,
  ROWS_SEPARATOR_LABEL,
  TREE_DRAWER_QUERY,
  TREE_SEPARATOR_LABEL,
  VIEWER_SEPARATOR_LABEL,
} from "./Layout";

/** Scroll review C2: the left panel folds to a rail (≥ 900px) or becomes a drawer (< 900px). */

let narrow = false;

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
  narrow = false;
  // Both drawer queries (viewer < 1200, tree < 900) match in the narrow case.
  vi.stubGlobal(
    "matchMedia",
    vi.fn((query: string) => ({
      matches: narrow && (query === TREE_DRAWER_QUERY || query.includes("1199.98")),
      media: query,
      addEventListener: () => {},
      removeEventListener: () => {},
    })),
  );
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "/v2/");
  resetCommandRegistry();
  resetAppStore({ route: { runId: null, collection: null }, viewerPane: "auto" });
  useAppStore.setState({ treeCollapsed: false, treeDrawerOpen: false, treeIsDrawer: false });
  useAppStore.getState().navigate({ runId: "r1", collection: "intake" });
});

afterEach(() => {
  cleanup();
  resetCommandRegistry();
  vi.unstubAllGlobals();
});

describe("left panel, wide layouts", () => {
  it("folds to the 36px rail and unfolds from its button", () => {
    render(<Layout />);
    expect(screen.getByTestId("tree-region").hidden).toBe(false);
    expect(screen.queryByTestId("tree-rail")).toBeNull();
    act(() => toggleTreePane());
    expect(useAppStore.getState().treeCollapsed).toBe(true);
    // Folded, not unmounted: the tree keeps its state, the heading is hidden.
    expect(screen.getByTestId("tree-region").hidden).toBe(true);
    const expand = document.getElementById(TREE_EXPAND_ID);
    expect(expand?.getAttribute("aria-label")).toBe("왼쪽 패널 펼치기");
    fireEvent.click(expand as HTMLElement);
    expect(useAppStore.getState().treeCollapsed).toBe(false);
    expect(screen.queryByTestId("tree-rail")).toBeNull();
  });

  it("the folded state is kept for the session like the viewer's (UX-round review)", () => {
    expect(storedTreeCollapsed()).toBe(false);
    act(() => toggleTreePane());
    expect(window.sessionStorage.getItem(TREE_COLLAPSED_KEY)).toBe("1");
    expect(storedTreeCollapsed()).toBe(true);
    // A reload starts folded: the panel mounts at the rail.
    resetAppStore({ route: useAppStore.getState().route, treeCollapsed: storedTreeCollapsed() });
    render(<Layout />);
    expect(screen.getByTestId("tree-rail")).toBeTruthy();
    act(() => toggleTreePane());
    expect(window.sessionStorage.getItem(TREE_COLLAPSED_KEY)).toBeNull();
  });

  it("the stage rail toggle says what it will do", () => {
    render(<StageRail />);
    const toggle = screen.getByTestId("tree-toggle");
    expect(toggle.getAttribute("aria-label")).toBe("왼쪽 패널 접기");
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-label")).toBe("왼쪽 패널 펼치기");
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
  });

  it("view.tree is a command (palette) that needs a case", async () => {
    registerCommands(caseCommands(new QueryClient()));
    expect(await runCommand("view.tree")).toEqual({ ok: true });
    expect(useAppStore.getState().treeCollapsed).toBe(true);
    useAppStore.getState().navigate({ runId: null, collection: null });
    expect((await runCommand("view.tree")).ok).toBe(false);
  });
});

describe("left panel drawer (< 900px)", () => {
  beforeEach(() => {
    narrow = true;
  });

  it("renders no tree column: a closed drawer opened from the stage rail", () => {
    // The Layout renders the stage rail (and its 탐색 toggle) itself.
    render(<Layout />);
    expect(useAppStore.getState().treeIsDrawer).toBe(true);
    expect(document.getElementById("pane-tree")).toBeNull();
    const drawer = screen.getByTestId("tree-drawer");
    expect(drawer.hidden).toBe(true);
    const toggle = screen.getByTestId("tree-toggle");
    expect(toggle.getAttribute("aria-label")).toBe("왼쪽 패널 열기");
    fireEvent.click(toggle);
    expect(useAppStore.getState().treeDrawerOpen).toBe(true);
    expect(drawer.hidden).toBe(false);
  });

  it("Esc, the scrim and picking another collection close it", () => {
    render(<Layout />);
    act(() => toggleTreePane());
    expect(useAppStore.getState().treeDrawerOpen).toBe(true);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(useAppStore.getState().treeDrawerOpen).toBe(false);

    act(() => toggleTreePane());
    fireEvent.click(document.querySelector(".drawer-scrim") as HTMLElement);
    expect(useAppStore.getState().treeDrawerOpen).toBe(false);

    act(() => toggleTreePane());
    act(() => useAppStore.getState().navigate({ runId: "r1", collection: "files" }));
    expect(useAppStore.getState().treeDrawerOpen).toBe(false);
  });

  it("shares the narrow pane area with the viewer drawer: one at a time, tree on top", () => {
    const s = useAppStore.getState;
    s().setOverlay("viewerDrawer", true);
    s().setOverlay("treeDrawer", true);
    expect(s().viewerDrawerOpen).toBe(false);
    expect(s().closeTopOverlay()).toBe(true);
    expect(s().treeDrawerOpen).toBe(false);
    s().setOverlay("treeDrawer", true);
    s().setOverlay("viewerDrawer", true);
    expect(s().treeDrawerOpen).toBe(false);
  });

  it("leaving the narrow layout closes the drawer", () => {
    const s = useAppStore.getState;
    s().setTreeIsDrawer(true);
    s().setOverlay("treeDrawer", true);
    s().setTreeIsDrawer(false);
    expect(s().treeDrawerOpen).toBe(false);
  });
});

describe("drawer focus (UX-round review)", () => {
  beforeEach(() => {
    narrow = true;
  });

  it("the tree drawer traps focus from the stage heading and Esc returns it to the 탐색 button", () => {
    render(<Layout />);
    const toggle = screen.getByTestId("tree-toggle");
    toggle.focus();
    fireEvent.click(toggle);
    const drawer = screen.getByTestId("tree-drawer");
    expect(drawer.getAttribute("role")).toBe("dialog");
    expect(document.activeElement?.id).toBe(STAGE_HEADING_ID);
    // Focus leaving the drawer (Tab past the end, a click outside) is pulled back in.
    toggle.focus();
    expect(drawer.contains(document.activeElement)).toBe(true);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(useAppStore.getState().treeDrawerOpen).toBe(false);
    expect(document.activeElement).toBe(screen.getByTestId("tree-toggle"));
    // The close button does the same.
    fireEvent.click(screen.getByTestId("tree-toggle"));
    expect(document.activeElement?.id).toBe(STAGE_HEADING_ID);
    fireEvent.click(screen.getByRole("button", { name: "왼쪽 패널 닫기 (Esc)" }));
    expect(document.activeElement).toBe(screen.getByTestId("tree-toggle"));
  });

  it("picking a node from the tree drawer sends focus to the list", async () => {
    render(<Layout />);
    act(() => toggleTreePane());
    expect(document.activeElement?.id).toBe(STAGE_HEADING_ID);
    act(() => useAppStore.getState().navigate({ runId: "r1", collection: "files" }));
    expect(useAppStore.getState().treeDrawerOpen).toBe(false);
    await waitFor(() => expect(document.activeElement?.id).toBe(MAIN_ID)); // focusMain waits a frame
  });

  it("the viewer drawer traps focus and closing returns it outside the drawer", () => {
    useAppStore.getState().navigate({ runId: "r1", collection: "files" });
    render(<Layout />);
    act(() => useAppStore.getState().setOverlay("viewerDrawer", true));
    const drawer = screen.getByTestId("viewer-region");
    expect(drawer.contains(document.activeElement)).toBe(true);
    (document.getElementById(MAIN_ID) as HTMLElement).focus();
    expect(drawer.contains(document.activeElement)).toBe(true);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(useAppStore.getState().viewerDrawerOpen).toBe(false);
    expect(drawer.contains(document.activeElement)).toBe(false);
    expect(document.activeElement).not.toBe(document.body);
  });
});

describe("resize separators (UX-round review)", () => {
  function separatorLabels(): (string | null)[] {
    return [...document.querySelectorAll('[role="separator"]')].map((el) => el.getAttribute("aria-label"));
  }

  it("every separator has an accessible name (two, three and classic layouts)", () => {
    render(<Layout />);
    expect(separatorLabels()).toEqual([TREE_SEPARATOR_LABEL]);
    act(() => useAppStore.getState().navigate({ runId: "r1", collection: "files" }));
    expect(separatorLabels()).toEqual([TREE_SEPARATOR_LABEL, VIEWER_SEPARATOR_LABEL]);
    act(() => useViewPrefs.getState().setClassicSplit(true));
    expect(separatorLabels()).toEqual([TREE_SEPARATOR_LABEL, ROWS_SEPARATOR_LABEL]);
    act(() => useViewPrefs.getState().setClassicSplit(false));
    expect(TREE_SEPARATOR_LABEL).toBe("탐색 패널 너비 조절");
    expect(VIEWER_SEPARATOR_LABEL).toBe("뷰어 너비 조절");
  });
});
