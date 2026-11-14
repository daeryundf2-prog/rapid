// T-144 follow-up: back/forward + 취소 on a screen with unsaved input keeps the address on the
// screen still shown without overwriting the history entry the browser moved to.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseHash } from "../router";
import { registerLeaveGuard } from "./leaveGuard";
import { resetAppStore, useAppStore } from "./store";

const s = () => useAppStore.getState();

/** history.back() and wait for the browser's popstate (jsdom traverses asynchronously). */
function back(): Promise<void> {
  return new Promise((resolve) => {
    window.addEventListener("popstate", () => resolve(), { once: true });
    window.history.back();
  });
}

let unregister: () => void = () => {};

beforeEach(() => {
  window.history.replaceState(null, "", "/v2/");
  resetAppStore({ route: { runId: null, collection: null } });
});

afterEach(() => {
  unregister();
  vi.unstubAllGlobals();
});

describe("leave guard and the history (T-144)", () => {
  it("back + 취소 keeps the entry the browser moved to", async () => {
    s().navigate({ runId: "r1", collection: "files" });
    s().navigate({ runId: "r1", collection: "intake" });
    // Unsaved input on the dashboard; the analyst answers 취소.
    unregister = registerLeaveGuard((prev, next) =>
      prev.collection === "intake" && next.collection !== "intake" ? "unsaved" : null,
    );
    const confirmSpy = vi.fn(() => false);
    vi.stubGlobal("confirm", confirmSpy);

    await back();
    // (The router listener may already have asked; the sync is idempotent.)
    s().syncRouteFromLocation(parseHash(window.location.hash));
    expect(confirmSpy).toHaveBeenCalledTimes(1);
    expect(s().route.collection).toBe("intake");
    expect(window.location.hash).toBe("#/case/r1/intake");

    // Saved (no guard any more): back again still reaches the files entry, not the one before it.
    unregister();
    await back();
    expect(window.location.hash).toBe("#/case/r1/explore/files");
    s().syncRouteFromLocation(parseHash(window.location.hash));
    expect(s().route.collection).toBe("files");
  });
});
