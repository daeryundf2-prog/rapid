import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ViewerTarget } from "../contracts/viewer";
import { parseHash } from "../router";
import { DENSITY_KEY, PANELS_KEY, THEME_KEY } from "./slices/prefs";
import { anyRunActive, currentRun } from "./slices/runs";
import { rowKeyOf } from "./slices/selection";
import { resetAppStore, useAppStore } from "./store";

const s = () => useAppStore.getState();

const target = (locator: string, runId = "r1"): ViewerTarget => ({
  ref: { collection: "files", locator },
  runId,
  sourcePath: `C:/e/${locator}`,
});

beforeEach(() => {
  window.history.replaceState(null, "", "/v2/");
  window.localStorage.clear();
  resetAppStore({ route: { runId: null, collection: null } });
});

afterEach(() => {
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.density;
});

describe("route slice", () => {
  it("navigate pushes a hash entry; patchRoute merges and clears undefined keys", () => {
    const before = window.history.length;
    s().navigate({ runId: "r1", collection: "files", q: "x" });
    expect(window.location.hash).toBe("#/case/r1/files?q=x");
    expect(window.history.length).toBe(before + 1);
    s().patchRoute({ q: undefined }, { replace: true });
    expect(window.location.hash).toBe("#/case/r1/files");
    expect(window.history.length).toBe(before + 1);
    expect(s().route).toEqual({ runId: "r1", collection: "files" });
  });

  it("syncRouteFromLocation (back/forward) follows the hash without writing it", () => {
    s().navigate({ runId: "r1", collection: "files" });
    window.history.replaceState(null, "", "/v2/#/case/r1/docs");
    s().syncRouteFromLocation(parseHash(window.location.hash));
    expect(s().route.collection).toBe("docs");
  });

  it("openCollection keeps the viewer row in the same run (U1) and drops it across runs", () => {
    s().navigate({ runId: "r1", collection: "files" });
    s().setViewerTarget(target("/candidates/1"));
    s().openCollection("timeline");
    expect(s().route.row?.locator).toBe("/candidates/1");
    expect(s().viewerTarget?.sourcePath).toBe("C:/e//candidates/1");
    s().openCollection("files", { runId: "r2" });
    expect(s().route.row).toBeUndefined();
    expect(s().viewerTarget).toBeNull();
  });

  it("restores a viewer target from a refreshed URL", () => {
    s().syncRouteFromLocation(parseHash("#/case/r1/files?row=files%7C%7C%2Fcandidates%2F3%7C&mode=hex"));
    expect(s().viewerTarget).toEqual({
      ref: { collection: "files", kind: undefined, locator: "/candidates/3", caseDbId: undefined },
      runId: "r1",
      sourcePath: null,
      preferredMode: "hex",
    });
  });
});

describe("selection slice", () => {
  it("toggles, de-duplicates and clears on collection change", () => {
    s().navigate({ runId: "r1", collection: "files" });
    s().setSelectedRows(["a", "a", "b"]);
    expect(s().selectedRowKeys).toEqual(["a", "b"]);
    s().toggleRowSelected("a");
    s().toggleRowSelected("c");
    expect(s().selectedRowKeys).toEqual(["b", "c"]);
    s().focusRow("b");
    s().patchRoute({ q: "filter" });
    expect(s().selectedRowKeys).toEqual(["b", "c"]);
    s().openCollection("docs");
    expect(s().selectedRowKeys).toEqual([]);
    expect(s().focusedRowKey).toBeNull();
  });

  it("row keys follow the GridRow convention", () => {
    expect(rowKeyOf({ collection: "timeline", locator: "/events/9" })).toBe("timeline:/events/9");
  });
});

describe("viewer slice", () => {
  it("mirrors the target into row= (replace) and mode= only for the same row", () => {
    s().navigate({ runId: "r1", collection: "files" });
    const len = window.history.length;
    s().setViewerTarget(target("/candidates/1"));
    expect(parseHash(window.location.hash).row?.locator).toBe("/candidates/1");
    s().setViewerMode("hex");
    expect(parseHash(window.location.hash).mode).toBe("hex");
    // Same row re-published by the grid keeps the mode; a new row clears it.
    s().setViewerTarget(target("/candidates/1"));
    expect(parseHash(window.location.hash).mode).toBe("hex");
    s().setViewerTarget(target("/candidates/2"));
    expect(parseHash(window.location.hash).mode).toBeUndefined();
    expect(window.history.length).toBe(len);
    s().setViewerTarget(null);
    expect(parseHash(window.location.hash).row).toBeUndefined();
  });
});

describe("automatic selection", () => {
  it("syncUrl:false loads the viewer without writing row=, and survives filter changes", () => {
    s().navigate({ runId: "r1", collection: "files" });
    s().setViewerTarget(target("/candidates/0"), { syncUrl: false });
    expect(window.location.hash).toBe("#/case/r1/files");
    s().patchRoute({ q: "x" }, { replace: true });
    expect(s().viewerTarget?.ref.locator).toBe("/candidates/0");
    s().setViewerTarget(target("/candidates/1"));
    expect(parseHash(window.location.hash).row?.locator).toBe("/candidates/1");
  });
});

describe("prefs slice", () => {
  it("persists an explicit theme under rapidtriage.v2.theme; null follows the OS", () => {
    s().setTheme("light");
    expect(window.localStorage.getItem(THEME_KEY)).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    s().toggleTheme();
    expect(s().theme).toBe("dark");
    s().setTheme(null);
    expect(window.localStorage.getItem(THEME_KEY)).toBeNull();
    expect(document.documentElement.dataset.theme).toBeUndefined();
  });

  it("cycles three densities and applies data-density", () => {
    expect(s().density).toBe("default");
    s().cycleDensity();
    expect(s().density).toBe("comfortable");
    expect(document.documentElement.dataset.density).toBe("comfortable");
    s().cycleDensity();
    expect(s().density).toBe("compact");
    expect(window.localStorage.getItem(DENSITY_KEY)).toBe("compact");
  });

  it("persists panel sizes", () => {
    s().setPanelLayout({ tree: 20, grid: 50, viewer: 30 });
    expect(JSON.parse(window.localStorage.getItem(PANELS_KEY) ?? "null")).toEqual({
      tree: 20,
      grid: 50,
      viewer: 30,
    });
  });
});

describe("overlay + runs slices", () => {
  it("closes the topmost overlay first", () => {
    s().setOverlay("viewerDrawer", true);
    s().setOverlay("help", true);
    expect(s().closeTopOverlay()).toBe(true);
    expect(s().helpOpen).toBe(false);
    expect(s().viewerDrawerOpen).toBe(true);
    expect(s().closeTopOverlay()).toBe(true);
    expect(s().closeTopOverlay()).toBe(false);
  });

  it("tracks the routed run and activity", () => {
    s().setRuns([
      { run_id: "a", status: "completed" },
      { run_id: "b", status: "running" },
    ]);
    s().navigate({ runId: "a", collection: "intake" });
    expect(currentRun(s())?.run_id).toBe("a");
    expect(anyRunActive(s())).toBe(true);
  });
});
