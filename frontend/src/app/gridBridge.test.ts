import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GridRow } from "../contracts/collection";
import { useGridLocalStore } from "../features/grid/adapter";
import { parseHash } from "../router";
import { resetAppStore, useAppStore } from "../state/store";
import { connectGridToShell } from "./gridBridge";

const s = () => useAppStore.getState();

function row(locator: string): GridRow {
  return {
    rowKey: `files:${locator}`,
    ref: { collection: "files", locator },
    title: locator,
    sourcePath: `C:/e${locator}`,
    timestamp: null,
    artifactType: null,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: {},
  };
}

function publish(r: GridRow) {
  useGridLocalStore.getState().publishFocusedRow(r, { ref: r.ref, runId: "r1", sourcePath: r.sourcePath });
}

let off: () => void;

beforeEach(() => {
  window.history.replaceState(null, "", "/v2/");
  resetAppStore({ route: { runId: null, collection: null } });
  useGridLocalStore.getState().publishFocusedRow(null, null);
  off = connectGridToShell();
});

afterEach(() => off());

describe("gridBridge automatic first row", () => {
  it("loads the first row into the viewer without writing row=", () => {
    s().navigate({ runId: "r1", collection: "files" });
    publish(row("/candidates/0"));
    expect(s().viewerTarget?.ref.locator).toBe("/candidates/0");
    expect(s().viewerRow?.rowKey).toBe("files:/candidates/0");
    expect(window.location.hash).toBe("#/case/r1/explore/files");
  });

  it("a click on the auto-focused first row is a user action: row= is written", () => {
    s().navigate({ runId: "r1", collection: "files" });
    const first = row("/candidates/0");
    publish(first);
    expect(window.location.hash).toBe("#/case/r1/explore/files");
    const main = document.createElement("main");
    main.id = "main";
    const rowEl = document.createElement("div");
    main.appendChild(rowEl);
    document.body.appendChild(main);
    rowEl.dispatchEvent(new Event("pointerdown", { bubbles: true }));
    publish(first); // the grid republishes the same row on mousedown
    expect(parseHash(window.location.hash).row).toEqual({ collection: "files", locator: "/candidates/0" });
    main.remove();
  });

  it("does not let row 0 clobber a pending deep link, then accepts the restored row", () => {
    window.history.replaceState(
      null,
      "",
      "/v2/#/case/r1/explore/files?row=files%7C%7C%2Fcandidates%2F9%7C&mode=meta",
    );
    s().syncRouteFromLocation(parseHash(window.location.hash));
    publish(row("/candidates/0"));
    expect(s().viewerTarget?.ref.locator).toBe("/candidates/9");
    publish(row("/candidates/9"));
    expect(s().viewerTarget?.sourcePath).toBe("C:/e/candidates/9");
    expect(parseHash(window.location.hash)).toMatchObject({
      mode: "meta",
      row: { locator: "/candidates/9" },
    });
  });
});

describe("gridBridge server sort and promoted columns", () => {
  it("grid sort / cols go to the URL and URL sort / cols come back to the grid", () => {
    s().navigate({ runId: "r1", collection: "artifacts", kind: "windows-prefetch" });
    useGridLocalStore.getState().setRoute({
      sort: { key: "details.run_count", order: "desc" },
      cols: ["details.run_count"],
    });
    expect(window.location.hash).toBe(
      "#/case/r1/explore/artifacts/windows-prefetch?sort=details.run_count:desc&cols=details.run_count",
    );
    s().navigate(parseHash("#/case/r1/explore/artifacts/windows-prefetch?sort=timestamp:asc"));
    expect(useGridLocalStore.getState().route.sort).toEqual({ key: "timestamp", order: "asc" });
    expect(useGridLocalStore.getState().route.cols).toBeUndefined();
    // Opening another kind drops both.
    s().openCollection("artifacts", { kind: "eventlog" });
    expect(useGridLocalStore.getState().route.sort).toBeUndefined();
  });
});
