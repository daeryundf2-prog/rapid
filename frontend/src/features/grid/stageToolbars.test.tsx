import { act, cleanup, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useFilterStore } from "../filters/filterStore";
import { useGridLocalStore } from "./adapter";
import { DataGrid } from "./DataGrid";
import { installFetch, jsonResponse, mockLayout, renderWithClient, resetGridStore } from "./testSupport";

vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: vi.fn(),
}));

let restoreLayout: () => void;
beforeEach(() => {
  resetGridStore();
  useFilterStore.getState().clearFilters();
  restoreLayout = mockLayout();
});
afterEach(() => {
  cleanup();
  restoreLayout();
  vi.unstubAllGlobals();
  useFilterStore.getState().clearFilters();
});

const kindChoices = () =>
  Array.from((screen.getByLabelText("종류") as HTMLSelectElement).options).map((o) => o.value);

describe("보고 toolbar 종류 (review B2-4)", () => {
  it("keeps every kind on offer after one is picked", async () => {
    installFetch({
      "/output-files": () =>
        jsonResponse({
          files: [
            { name: "artifacts_browser", path: "C:/o/a.json", size: 1, exists: true },
            { name: "case_db", path: "C:/o/case.db", size: 2, exists: true },
          ],
        }),
    });
    useGridLocalStore.getState().setRoute({ runId: "run-1", collection: { id: "outputs" } });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(kindChoices()).toEqual(["", "아티팩트", "케이스 DB"]));
    act(() => useFilterStore.getState().patchFilters({ types: ["케이스 DB"] }));
    await waitFor(() => expect(screen.queryAllByRole("row").filter((r) => r.dataset.index).length).toBe(1));
    expect(kindChoices()).toEqual(["", "아티팩트", "케이스 DB"]);
  });
});

describe("column menu (review B2-6 + AXIOM density nit)", () => {
  it("출처 중심 shows 시각, and 항목 (not the first column) is the locked one", async () => {
    const { artifactColumnsForKind } = await import("./columns/artifacts");
    const { lockedColumnId, presetColumnIds } = await import("./columns");
    // Every artifact = the mixed-family layout (U-F8): 유형 · 항목 · 특이사항 · 4 summary columns.
    const columns = artifactColumnsForKind(undefined);
    expect(columns.slice(0, 7).map((c) => c.id)).toEqual([
      "type",
      "title",
      "flags",
      "sum:main",
      "sum:support",
      "sum:extra",
      "sum:time",
    ]);
    expect(presetColumnIds(columns, "source")).toContain("timestamp");
    expect(lockedColumnId(columns)).toBe("title");
  });

  it("picking AXIOM gives 32px rows without changing the global density", async () => {
    const { filesHandler } = await import("./testSupport");
    installFetch({ "/files": filesHandler(20) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(screen.queryAllByRole("row").some((r) => r.dataset.index)).toBe(true));
    act(() => screen.getByTestId("filter-popover-button").click());
    const presetSelect = screen.getByLabelText("열 구성") as HTMLSelectElement;
    const { fireEvent } = await import("@testing-library/react");
    fireEvent.change(presetSelect, { target: { value: "axiom" } });
    expect(useGridLocalStore.getState().density).toBe("default");
    await waitFor(() => {
      const row = screen.queryAllByRole("row").find((r) => r.dataset.index === "0") as HTMLElement;
      expect(row.style.height).toBe("32px");
    });
    window.localStorage.removeItem("rapidtriage.grid.preset");
  });
});
