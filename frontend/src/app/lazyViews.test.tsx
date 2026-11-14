// T-116: the view switch's non-column views are lazy chunks — the switch renders at once, the
// view shows "… 불러오는 중" (role=status) and then itself once its chunk resolves.
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
    expect(screen.getByRole("status").textContent).toContain("썸네일 보기 불러오는 중");
    await waitFor(() => expect(screen.queryByTestId("lazy-view-loading")).toBeNull());
    const body = container.querySelector(".view-switch-body");
    expect(body?.children.length).toBeGreaterThan(0);
    expect(screen.queryByTestId("lazy-view-error")).toBeNull();
  });
});
