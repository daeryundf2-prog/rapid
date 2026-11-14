// T-036 browser check (verify-wb5-7 G1): after the status menu's "관련 있음 (해제)", a mark made
// with the R key (grid / shell path) must show on the viewer chip and in the list on screen.

import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { resetCaseDbHandles } from "../grid/reviewActions";
import { registerRowSource, resetRowSources } from "../review/rowSource";
import { resetViewerAdapter, setViewerRowContext, setViewerTarget } from "./adapter";
import { targetAsGridRow } from "./citation";
import { installFetch, target } from "./testSupport";
import { ViewerToolbar } from "./ViewerToolbar";

const ctx = {
  runId: "run-1",
  collection: "files",
  selectedRowKeys: [],
  focusedRowKey: null,
  viewerHasTarget: true,
  runIsActive: false,
};
const markCommand = {
  id: "viewer.mark.relevant",
  label: "표시: 관련 있음",
  group: "viewer" as const,
  run: () => {},
};

beforeEach(() => {
  resetViewerAdapter();
  resetRowSources();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  resetCaseDbHandles();
  resetRowSources();
});

describe("viewer un-press, then R (T-036)", () => {
  it("the chip and the list follow the row after 해제", async () => {
    installFetch({
      ensure: () => ({ database: "D:/out/rapidtriage-case.db", case_id: "run-out" }),
      "review-history": () => ({ entries: [] }),
      "review-batch": () => ({}),
    });
    const viewerTarget = target({ sourcePath: "C:/evidence/a.txt" });
    const base = targetAsGridRow(viewerTarget);
    const relevant: GridRow = { ...base, reviewStatus: "relevant" };
    const patches: ((row: GridRow) => GridRow)[] = [];
    registerRowSource({
      getSelectedRows: () => [],
      patchRows: (_keys, patch) => {
        patches.push(patch);
        return () => {};
      },
    });
    act(() => setViewerTarget(viewerTarget, relevant));
    render(
      <ViewerToolbar
        sourceCommands={[]}
        markCommands={[markCommand]}
        ctx={ctx}
        onRun={() => Promise.resolve()}
        rowsForSource={{ reason: "없음", run: () => {} }}
      />,
    );
    const chip = () => screen.getByTestId("viewer-review-status");
    expect(chip().textContent).toBe("관련 있음");
    // 관련 있음 (해제) from the status menu.
    fireEvent.click(screen.getByTestId("viewer-review-status-menu"));
    fireEvent.click(document.querySelector('[data-command="viewer.mark.relevant"]') as HTMLElement);
    await waitFor(() => expect(chip().textContent).toBe("미검토"));
    // The list on screen was patched back too.
    expect(patches).toHaveLength(1);
    expect(patches[0]?.(relevant).reviewStatus).toBeNull();
    // The list (and the store row) show the un-press, then R marks the row from the grid.
    act(() => setViewerRowContext({ ...base, reviewStatus: null }));
    act(() => setViewerRowContext({ ...base, reviewStatus: "relevant" }));
    expect(chip().textContent).toBe("관련 있음");
  });
});
