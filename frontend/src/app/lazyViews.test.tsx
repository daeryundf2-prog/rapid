// T-116: the view switch's non-column views are lazy chunks — the switch renders at once, the
// view shows "… 불러오는 중" (aria-busy, NOT a second live region: the app root's LiveRegion is the
// only polite region) and then itself once its chunk resolves.
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetCommandRegistry } from "../commands/registry";
import {
  installFetch,
  jsonResponse,
  mockLayout,
  queryWrapper,
  resetGridStore,
} from "../features/grid/testSupport";
import { resetAppStore, useAppStore } from "../state/store";
import { ViewSwitch } from "./ViewSwitch";

let restoreLayout: () => void = () => {};

beforeEach(() => {
  resetCommandRegistry();
  resetAppStore();
  resetGridStore();
  restoreLayout = mockLayout(800, 600);
});

afterEach(() => {
  cleanup();
  restoreLayout();
  resetCommandRegistry();
  vi.unstubAllGlobals();
});

describe("lazy views in the view switch", () => {
  it("shows 불러오는 중 while the view's chunk loads, then the view in place of the grid", async () => {
    installFetch({ "/files": () => jsonResponse({ candidates: [], total: 0 }) });
    act(() => useAppStore.getState().navigate({ runId: "run-1", collection: "files", view: "thumbnails" }));
    const { wrapper } = queryWrapper();
    const { container } = render(
      <ViewSwitch>
        <div>GRID</div>
      </ViewSwitch>,
      { wrapper },
    );
    expect(screen.queryByText("GRID")).toBeNull();
    // The switch is usable while the chunk loads; the body says what is loading.
    expect(screen.getByRole("toolbar", { name: "보기 전환" })).toBeTruthy();
    const loading = screen.getByTestId("lazy-view-loading");
    expect(loading.textContent).toContain("썸네일 보기 불러오는 중");
    expect(loading.getAttribute("aria-busy")).toBe("true");
    // No live region of its own (a11y rule 9: exactly one polite region, the root LiveRegion).
    expect(screen.queryByRole("status")).toBeNull();
    expect(container.querySelector("[aria-live]")).toBeNull();
    // A cold first import of the view chunk (vite transform) can outlast waitFor's 1 s default.
    await waitFor(() => expect(screen.queryByTestId("lazy-view-loading")).toBeNull(), { timeout: 15_000 });
    const body = container.querySelector(".view-switch-body");
    expect(body?.children.length).toBeGreaterThan(0);
    expect(screen.queryByTestId("lazy-view-error")).toBeNull();
  });
});
