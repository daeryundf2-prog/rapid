import { act, cleanup, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useGridLocalStore } from "./adapter";
import { DataGrid } from "./DataGrid";
import { filesHandler, installFetch, mockLayout, renderWithClient, resetGridStore } from "./testSupport";

vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: vi.fn(),
}));

let restoreLayout: () => void;
beforeEach(() => {
  resetGridStore();
  restoreLayout = mockLayout();
});
afterEach(() => {
  cleanup();
  restoreLayout();
  vi.unstubAllGlobals();
});

const rows = () => screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index"));

describe("grid selection scope (review B2-1)", () => {
  it("a selection made in one collection does not follow the grid into another", async () => {
    installFetch({ "/files": filesHandler(40) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBeGreaterThan(0));
    const key = rows()[0]?.getAttribute("data-row-key") as string;
    act(() => useGridLocalStore.getState().select([key]));
    expect(useGridLocalStore.getState().selectedKeys.size).toBe(1);

    // Same grid, another collection (e.g. 탐색 → 보고 with Alt+5): the selection is gone.
    act(() => useGridLocalStore.getState().setRoute({ collection: { id: "files", category: "documents" } }));
    await waitFor(() => expect(useGridLocalStore.getState().selectedKeys.size).toBe(0));
  });

  it("re-entering the same grid keeps the selection", () => {
    const store = useGridLocalStore.getState();
    store.enterSelectionScope("run-1|files");
    store.select(["a"]);
    useGridLocalStore.getState().enterSelectionScope("run-1|files");
    expect(useGridLocalStore.getState().selectedKeys.size).toBe(1);
    useGridLocalStore.getState().enterSelectionScope("run-1|outputs");
    expect(useGridLocalStore.getState().selectedKeys.size).toBe(0);
  });
});

describe("batch bar reserve (review B2-7)", () => {
  it("reserves the bar's measured height under the rows, not a fixed 64px", async () => {
    installFetch({ "/files": filesHandler(40) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBeGreaterThan(0));
    const key = rows()[0]?.getAttribute("data-row-key") as string;
    act(() => useGridLocalStore.getState().select([key]));
    const root = document.querySelector(".grid-root") as HTMLElement;
    // mockLayout() gives every element a 600px offsetHeight: the bar "wrapped" to 600px.
    await waitFor(() => expect(root.style.getPropertyValue("--batch-reserve")).toBe("624px"));
    act(() => useGridLocalStore.getState().select([]));
    await waitFor(() => expect(root.style.getPropertyValue("--batch-reserve")).toBe(""));
  });
});
