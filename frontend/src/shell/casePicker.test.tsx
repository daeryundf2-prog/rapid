import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { RunListItem } from "../api/runs";
import { DELETE_RUN_LABEL, useCaseDialogs } from "../features/case/dialogs";
import { isMacPlatform, keyLabel } from "../shortcuts";
import { resetAppStore, useAppStore } from "../state/store";
import { CasePickerCombobox } from "./CasePickerCombobox";
import {
  casePickerOptions,
  moveActiveIndex,
  RUN_ACTIVE_DELETE_REASON,
  runDeleteReason,
  shortDateTime,
} from "./casePicker";

const runs: RunListItem[] = [
  {
    run_id: "old11111",
    status: "completed",
    created_at: "2026-10-01T09:00:00Z",
    request: { root: "C:/cases/alpha.E01", mode: "fraud" } as RunListItem["request"],
  },
  {
    run_id: "new22222",
    status: "failed",
    created_at: "2026-10-12T09:00:00Z",
    request: { root: "D:/evidence/beta", mode: "hacking" } as RunListItem["request"],
  },
  { run_id: "mid33333", status: "running", created_at: "2026-10-05T09:00:00Z" },
];

describe("case picker model (review #5)", () => {
  it("lists the most recent case first with name, mode, date, run id and a status tone", () => {
    const options = casePickerOptions(runs);
    expect(options.map((o) => o.runId)).toEqual(["new22222", "mid33333", "old11111"]);
    expect(options[0]).toMatchObject({ name: "beta", mode: "침해사고", status: "failed", tone: "danger" });
    expect(options[1]).toMatchObject({ name: "mid33333", mode: "모드 없음", tone: "info" });
    expect(options[2]?.tone).toBe("ok");
    expect(options[0]?.date).toBe(shortDateTime("2026-10-12T09:00:00Z"));
    expect(shortDateTime("2026-10-12T09:00:00Z", "Asia/Seoul")).toBe("2026-10-12 18:00");
    expect(shortDateTime(undefined)).toBe("");
  });

  it("narrows by every search term against name, mode and run id", () => {
    expect(casePickerOptions(runs, "alpha").map((o) => o.runId)).toEqual(["old11111"]);
    expect(casePickerOptions(runs, "침해").map((o) => o.runId)).toEqual(["new22222"]);
    expect(casePickerOptions(runs, "mid3").map((o) => o.runId)).toEqual(["mid33333"]);
    expect(casePickerOptions(runs, "beta 부정")).toEqual([]);
  });

  it("moves the active row with wrap-around", () => {
    expect(moveActiveIndex(-1, 1, 3)).toBe(0);
    expect(moveActiveIndex(-1, -1, 3)).toBe(2);
    expect(moveActiveIndex(2, 1, 3)).toBe(0);
    expect(moveActiveIndex(0, -1, 3)).toBe(2);
    expect(moveActiveIndex(0, 1, 0)).toBe(-1);
  });
});

describe("case combobox (review #5)", () => {
  beforeEach(() => {
    resetAppStore();
    act(() => useAppStore.getState().setRuns(runs as never));
  });
  afterEach(cleanup);

  const open = () => {
    fireEvent.click(screen.getByTestId("case-picker"));
    return screen.getByRole("combobox", { name: "런 검색" });
  };

  it("opens a popover with search on top; ↓ / ↑ move, Enter opens the case", () => {
    render(<CasePickerCombobox />);
    const trigger = screen.getByTestId("case-picker");
    expect(trigger.getAttribute("aria-haspopup")).toBe("dialog");
    const search = open();
    expect(trigger.getAttribute("aria-expanded")).toBe("true");
    expect(document.activeElement).toBe(search);
    const list = screen.getByRole("listbox", { name: "런" });
    const options = within(list).getAllByRole("option");
    expect(options.map((o) => o.querySelector(".case-picker-option-name")?.textContent)).toEqual([
      "beta",
      "mid33333",
      "alpha.E01",
    ]);
    expect(options[0]?.getAttribute("aria-selected")).toBe("true");
    expect(search.getAttribute("aria-activedescendant")).toBe(options[0]?.id);
    fireEvent.keyDown(search, { key: "ArrowDown" });
    fireEvent.keyDown(search, { key: "ArrowDown" });
    expect(search.getAttribute("aria-activedescendant")).toBe(options[2]?.id);
    fireEvent.keyDown(search, { key: "ArrowUp" });
    fireEvent.keyDown(search, { key: "Enter" });
    expect(useAppStore.getState().route).toMatchObject({ runId: "mid33333", collection: "intake" });
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it("Esc closes and returns focus; typing on the closed trigger starts the search (typeahead)", () => {
    render(<CasePickerCombobox />);
    const trigger = screen.getByTestId("case-picker");
    const search = open();
    fireEvent.keyDown(search, { key: "Escape" });
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    fireEvent.keyDown(trigger, { key: "a" });
    const typed = screen.getByRole("combobox", { name: "런 검색" }) as HTMLInputElement;
    expect(typed.value).toBe("a");
    const names = within(screen.getByRole("listbox"))
      .getAllByRole("option")
      .map((o) => o.querySelector(".case-picker-option-name")?.textContent);
    expect(names).toEqual(["beta", "alpha.E01"]);
  });

  it("shows the current case on the trigger and marks it in the list", () => {
    act(() => useAppStore.getState().navigate({ runId: "old11111", collection: "intake" }));
    render(<CasePickerCombobox />);
    expect(screen.getByTestId("case-picker").textContent).toContain("alpha.E01 · 문서·부정 조사");
    open();
    const current = screen.getByRole("option", { current: true });
    expect(current.getAttribute("aria-selected")).toBe("true");
    expect(current.querySelector(".status-dot.ok")?.getAttribute("aria-label")).toBe("완료");
  });

  it("deletes a run from the picker row through the T-034 confirm, never directly (r8 verify F3)", () => {
    useCaseDialogs.getState().close();
    render(<CasePickerCombobox />);
    const trigger = screen.getByTestId("case-picker");
    const search = open();
    // Keyboard: the labelled button under the list acts on the active row (beta, failed).
    const button = screen.getByRole("button", { name: `beta ${DELETE_RUN_LABEL}` });
    expect(button.getAttribute("aria-disabled")).toBeNull();
    // A running run cannot be deleted: the button says why and does nothing.
    fireEvent.keyDown(search, { key: "ArrowDown" });
    const running = screen.getByRole("button", { name: `mid33333 ${DELETE_RUN_LABEL}` });
    expect(running.getAttribute("aria-disabled")).toBe("true");
    expect(running.getAttribute("title")).toBe(RUN_ACTIVE_DELETE_REASON);
    fireEvent.click(running);
    expect(useCaseDialogs.getState().open).toBeNull();
    fireEvent.keyDown(search, { key: "ArrowUp" });
    fireEvent.click(screen.getByRole("button", { name: `beta ${DELETE_RUN_LABEL}` }));
    expect(useCaseDialogs.getState()).toMatchObject({ open: "delete", deleteRunId: "new22222" });
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    // Pointer: each deletable row has an aria-hidden trash icon (the running row has none).
    useCaseDialogs.getState().close();
    open();
    const rowIcons = screen.getAllByTestId("case-picker-row-delete");
    expect(rowIcons).toHaveLength(2);
    expect(rowIcons.every((icon) => icon.getAttribute("aria-hidden") === "true")).toBe(true);
    fireEvent.click(rowIcons[1] as HTMLElement);
    expect(useCaseDialogs.getState()).toMatchObject({ open: "delete", deleteRunId: "old11111" });
    // The row click did not also open the run.
    expect(useAppStore.getState().route.runId).not.toBe("old11111");
    expect(runDeleteReason("queued")).toBe(RUN_ACTIVE_DELETE_REASON);
    expect(runDeleteReason("completed")).toBeUndefined();
    useCaseDialogs.getState().close();
  });
});

describe("palette key label (review #14)", () => {
  it("is ⌘K on Apple platforms and Ctrl K everywhere else", () => {
    expect(isMacPlatform("MacIntel")).toBe(true);
    expect(isMacPlatform("iPhone")).toBe(true);
    expect(isMacPlatform("Win32")).toBe(false);
    expect(isMacPlatform("Linux x86_64")).toBe(false);
    expect(keyLabel("Ctrl+K", true)).toBe("⌘K");
    expect(keyLabel("Ctrl+K", false)).toBe("Ctrl K");
    expect(keyLabel("Alt+ArrowLeft", true)).toBe("Alt ←");
  });
});
