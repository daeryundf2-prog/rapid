import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetAppStore, useAppStore } from "../state/store";
import { focusGridWhenReady, MAIN_ID } from "./builtin";

function ensureMain(): HTMLElement {
  let main = document.getElementById(MAIN_ID);
  if (!main) {
    main = document.createElement("main");
    main.id = MAIN_ID;
    main.tabIndex = -1;
    document.body.append(main);
  }
  return main;
}

function mountGrid(rowKey: string | null, busy = false): HTMLElement | null {
  const main = ensureMain();
  main.innerHTML = "";
  const grid = document.createElement("div");
  grid.setAttribute("role", "grid");
  grid.setAttribute("aria-busy", String(busy));
  main.append(grid);
  if (!rowKey) return null;
  const row = document.createElement("div");
  row.setAttribute("role", "row");
  row.tabIndex = 0;
  row.dataset.rowKey = rowKey;
  grid.append(row);
  return row;
}

const later = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

beforeEach(() => {
  document.body.innerHTML = "";
  window.history.replaceState(null, "", "/v2/");
  resetAppStore({ route: { runId: null, collection: null } });
  useAppStore.getState().navigate({ runId: "r1", collection: "files" });
});

afterEach(() => {
  document.body.innerHTML = "";
});

describe("focusGridWhenReady", () => {
  it("after a route change with async rows, document.activeElement is the new roving row", async () => {
    mountGrid("files:/candidates/0");
    const search = document.createElement("input");
    document.body.append(search);
    search.focus();
    useAppStore.getState().openCollection("search", { q: "powershell" });
    focusGridWhenReady({ settleMs: 10_000 });
    mountGrid(null, true); // page loading
    await later(50);
    expect(document.activeElement).toBe(search);
    const row = mountGrid("documents:/results/3"); // first page arrives
    await vi.waitFor(() => expect(document.activeElement).toBe(row));
  });

  it("re-applies focus once when the virtualised row re-mounts right after focusing", async () => {
    const first = mountGrid("timeline:/events/0");
    useAppStore.getState().openCollection("timeline");
    focusGridWhenReady({ settleMs: 0, guardMs: 500 });
    await vi.waitFor(() => expect(document.activeElement).toBe(first));
    const remounted = mountGrid("timeline:/events/0"); // same row, new element; focus falls to body
    await vi.waitFor(() => expect(document.activeElement).toBe(remounted));
  });

  it("falls back to #main on the intake summary", async () => {
    const main = ensureMain();
    useAppStore.getState().openCollection("intake");
    focusGridWhenReady();
    await vi.waitFor(() => expect(document.activeElement).toBe(main));
  });

  it("is cancelled when the analyst clicks elsewhere first", async () => {
    mountGrid("files:/candidates/0");
    const other = document.createElement("button");
    document.body.append(other);
    focusGridWhenReady({ settleMs: 10_000 });
    other.dispatchEvent(new Event("pointerdown", { bubbles: true }));
    other.focus();
    mountGrid("docs:/results/1");
    await later(80);
    expect(document.activeElement).toBe(other);
  });

  it("keeps the request alive when J is pressed on the page before rows arrive, then focuses the row", async () => {
    mountGrid("files:/candidates/0");
    useAppStore.getState().openCollection("search", { q: "powershell" });
    focusGridWhenReady({ settleMs: 10_000 });
    mountGrid(null, true);
    (document.activeElement as HTMLElement | null)?.blur();
    document.body.dispatchEvent(new KeyboardEvent("keydown", { key: "j", bubbles: true }));
    await later(30);
    const row = mountGrid("search:/hits/0");
    await vi.waitFor(() => expect(document.activeElement).toBe(row));
  });

  it("forwards a grid key pressed on the page to the ready row", async () => {
    useAppStore.getState().openCollection("timeline");
    focusGridWhenReady({ settleMs: 10_000 });
    const row = mountGrid("timeline:/events/0") as HTMLElement;
    const seen: string[] = [];
    row.addEventListener("keydown", (event) => seen.push(event.key));
    const original = new KeyboardEvent("keydown", { key: "j", bubbles: true, cancelable: true });
    document.body.dispatchEvent(original);
    expect(document.activeElement).toBe(row);
    expect(seen).toEqual(["j"]);
    expect(original.defaultPrevented).toBe(true);
  });

  it("re-applies focus once when a closing overlay restores focus outside #main", async () => {
    const opener = document.createElement("button");
    document.body.append(opener);
    const row = mountGrid("timeline:/events/0");
    useAppStore.getState().openCollection("timeline");
    focusGridWhenReady({ settleMs: 0, guardMs: 500 });
    await vi.waitFor(() => expect(document.activeElement).toBe(row));
    opener.focus(); // e.g. a dialog's focus-return after its unmount
    await vi.waitFor(() => expect(document.activeElement).toBe(row));
  });

  it("stops guarding once the analyst presses a key on the row (Enter may move focus to the viewer)", async () => {
    const viewer = document.createElement("section");
    viewer.tabIndex = -1;
    document.body.append(viewer);
    const row = mountGrid("timeline:/events/0") as HTMLElement;
    useAppStore.getState().openCollection("timeline");
    focusGridWhenReady({ settleMs: 0, guardMs: 500 });
    await vi.waitFor(() => expect(document.activeElement).toBe(row));
    row.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    viewer.focus();
    await later(80);
    expect(document.activeElement).toBe(viewer);
  });

  it("is cancelled when the analyst types into a field", async () => {
    mountGrid("files:/candidates/0");
    const field = document.createElement("input");
    document.body.append(field);
    focusGridWhenReady({ settleMs: 10_000 });
    field.focus();
    field.dispatchEvent(new KeyboardEvent("keydown", { key: "a", bubbles: true }));
    mountGrid("docs:/results/1");
    await later(80);
    expect(document.activeElement).toBe(field);
  });
});
