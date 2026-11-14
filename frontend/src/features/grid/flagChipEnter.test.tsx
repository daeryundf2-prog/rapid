// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
// R7 stage 1 re-review R-12: in the 검토 특이사항 list, Enter on a focused 특이사항 chip opened its
// evidence popover (and the row was already the viewer's) — Enter now opens the viewer only;
// the popover stays on click / Space.
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useGridLocalStore } from "./adapter";
import { DataGrid } from "./DataGrid";
import {
  fileCandidates,
  installFetch,
  jsonResponse,
  mockLayout,
  renderWithClient,
  resetGridStore,
} from "./testSupport";

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

const FLAG = [{ id: "r7-test-rule", grade: "B", label: "시험 규칙" }];

async function renderFlagged() {
  installFetch({
    "/files": (url) => {
      const offset = Number(url.searchParams.get("offset") ?? 0);
      const limit = Number(url.searchParams.get("limit") ?? 0);
      const rows = fileCandidates(offset, Math.min(offset + limit, 5)).map((row) => ({
        ...row,
        flags: FLAG,
      }));
      return jsonResponse({ candidates: rows, total: 5, offset, limit });
    },
  });
  renderWithClient(<DataGrid />);
  await waitFor(() => expect(document.querySelectorAll("button.flag-cell").length).toBeGreaterThan(1));
}

const chipOf = (index: number) =>
  document.querySelector(`[data-index="${index}"] button.flag-cell`) as HTMLButtonElement;

describe("R-12: 특이사항 chip keys", () => {
  it("Enter on a focused chip opens the viewer for its row, not the popover", async () => {
    await renderFlagged();
    const chip = chipOf(2);
    chip.focus();
    const enter = fireEvent.keyDown(chip, { key: "Enter" });
    // The grid handled it (preventDefault keeps the button from clicking itself).
    expect(enter).toBe(false);
    await waitFor(() => expect(useGridLocalStore.getState().target?.ref.locator).toBe("/candidates/2"));
    expect(document.querySelector(".flag-popover")).toBeNull();
    expect(chip.getAttribute("aria-expanded")).toBe("false");
  });

  it("a click (and Space, a native button click) still opens the evidence popover", async () => {
    await renderFlagged();
    fireEvent.click(chipOf(1));
    await waitFor(() => expect(screen.getByRole("dialog", { name: "특이사항 근거" })).toBeTruthy());
    expect(chipOf(1).getAttribute("aria-expanded")).toBe("true");
  });

  it("other keys on the chip stay with the chip (Space is not the grid's selection toggle)", async () => {
    await renderFlagged();
    const chip = chipOf(1);
    chip.focus();
    const space = fireEvent.keyDown(chip, { key: " " });
    expect(space).toBe(true);
    expect(useGridLocalStore.getState().selectedKeys.size).toBe(0);
  });
});
