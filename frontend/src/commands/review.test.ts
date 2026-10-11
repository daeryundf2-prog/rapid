import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { connectViewerToShell } from "../app/viewerBridge";
import type { ViewerTarget } from "../contracts/viewer";
import { resetCaseDbHandles } from "../features/grid/reviewActions";
import {
  getViewerRouteMode,
  getViewerTarget,
  resetViewerAdapter,
  setViewerRouteMode,
  setViewerTarget,
} from "../features/viewer/adapter";
import { parseHash } from "../router";
import { dispatchShortcut } from "../shortcuts";
import { resetAppStore, useAppStore } from "../state/store";
import { caseCommands, NO_RUN_REASON, ROWS_FOR_SOURCE_INTAKE_REASON } from "./builtin";
import { registerCommands, resetCommandRegistry, runCommand } from "./registry";
import { NO_ROW_REASON, reviewCommands } from "./review";

const s = () => useAppStore.getState();
const target = (locator: string): ViewerTarget => ({
  ref: { collection: "files", locator },
  runId: "r1",
  sourcePath: `C:/e/dir/file${locator.slice(-1)}.txt`,
});

let posts: Array<{ url: string; body: unknown }>;

beforeEach(() => {
  resetCommandRegistry();
  resetViewerAdapter();
  window.history.replaceState(null, "", "/v2/");
  resetAppStore({ route: { runId: null, collection: null } });
  posts = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      posts.push({ url: String(url), body: init?.body ? JSON.parse(String(init.body)) : null });
      const payload = String(url).includes("/case-db/ensure")
        ? { database: "D:/out/rapidtriage-case.db", case_id: "run-out" }
        : { ok: true };
      return new Response(JSON.stringify(payload), { headers: { "content-type": "application/json" } });
    }),
  );
  registerCommands([...reviewCommands(null), ...caseCommands({ invalidateQueries: vi.fn() } as never)]);
});

afterEach(() => {
  resetCommandRegistry();
  vi.unstubAllGlobals();
  resetCaseDbHandles();
});

describe("review keys", () => {
  it("explain why they cannot run", async () => {
    expect(await runCommand("review.mark.relevant")).toEqual({ ok: false, reason: NO_RUN_REASON });
    s().navigate({ runId: "r1", collection: "files" });
    expect(await runCommand("review.priority.3")).toEqual({ ok: false, reason: NO_ROW_REASON });
  });

  it("R marks the context row through the shared bookmark/review implementation", async () => {
    s().navigate({ runId: "r1", collection: "files" });
    s().setViewerTarget(target("/candidates/1"));
    const row = document.createElement("div");
    row.setAttribute("role", "row");
    document.body.append(row);
    const event = new KeyboardEvent("keydown", { key: "r", bubbles: true, cancelable: true });
    Object.defineProperty(event, "target", { value: row });
    expect(dispatchShortcut(event)).toBe(true);
    await vi.waitFor(() => expect(posts).toHaveLength(2));
    expect(posts.map((p) => p.url)).toEqual(["/api/runs/r1/case-db/ensure", "/api/case-db/review-batch"]);
    expect(posts[1]?.body).toMatchObject({
      case_id: "run-out",
      run_id: "r1",
      status: "relevant",
      targets: [{ collection: "files", locator: "/candidates/1" }],
    });
    row.remove();
  });

  it("1–5 add a priority tag", async () => {
    s().navigate({ runId: "r1", collection: "files" });
    s().setViewerTarget(target("/candidates/2"));
    expect(await runCommand("review.priority.3")).toEqual({ ok: true });
    const batch = posts.find((p) => p.url === "/api/case-db/review-batch");
    expect(batch?.body).toMatchObject({
      add_tags: ["우선순위 3"],
      targets: [{ collection: "files", locator: "/candidates/2" }],
    });
  });
});

describe("navigate.rows-for-source", () => {
  it("filters the current collection by the viewer row's source path", async () => {
    s().navigate({ runId: "r1", collection: "timeline" });
    s().setViewerTarget(target("/candidates/4"));
    expect(await runCommand("navigate.rows-for-source")).toEqual({ ok: true });
    expect(s().route).toMatchObject({ collection: "timeline", q: "C:/e/dir/file4.txt" });
    // Already filtered to this source: running it again would change nothing, so it says so.
    expect(await runCommand("navigate.rows-for-source")).toEqual({
      ok: false,
      reason: "이미 이 원본에서 나온 행만 표시하고 있습니다",
    });
    s().openCollection("outputs");
    await runCommand("navigate.rows-for-source");
    expect(s().route.collection).toBe("files");
  });

  it("is disabled with a reason on the intake dashboard (no row list), even with a leftover target", async () => {
    s().navigate({ runId: "r1", collection: "intake" });
    s().setViewerTarget(target("/candidates/4"));
    expect(await runCommand("navigate.rows-for-source")).toEqual({
      ok: false,
      reason: ROWS_FOR_SOURCE_INTAKE_REASON,
    });
    expect(s().route.collection).toBe("intake");
  });
});

describe("viewerBridge", () => {
  it("syncs target and mode=, both ways", () => {
    s().navigate({ runId: "r1", collection: "files" });
    const off = connectViewerToShell();
    s().setViewerTarget(target("/candidates/1"));
    expect(getViewerTarget()?.ref.locator).toBe("/candidates/1");
    // Viewer tab choice → URL.
    setViewerRouteMode("hex");
    expect(parseHash(window.location.hash).mode).toBe("hex");
    // Viewer history (Alt ←) → store + URL; mode resets for the new row.
    setViewerTarget(target("/candidates/7"));
    expect(s().viewerTarget?.ref.locator).toBe("/candidates/7");
    expect(parseHash(window.location.hash).row?.locator).toBe("/candidates/7");
    expect(getViewerRouteMode()).toBeUndefined();
    off();
  });

  it("holds a URL-restored row until the grid resolves it, then restores mode=", () => {
    const off = connectViewerToShell();
    window.history.replaceState(
      null,
      "",
      "/v2/#/case/r1/files?row=files%7C%7C%2Fcandidates%2F5%7C&mode=meta",
    );
    s().syncRouteFromLocation(parseHash(window.location.hash));
    expect(s().viewerTarget?.sourcePath).toBeNull();
    expect(getViewerTarget()).toBeNull();
    s().setViewerTarget(target("/candidates/5"), { syncUrl: false });
    expect(getViewerTarget()?.sourcePath).toBe("C:/e/dir/file5.txt");
    expect(getViewerRouteMode()).toBe("meta");
    expect(parseHash(window.location.hash).mode).toBe("meta");
    off();
  });
});
