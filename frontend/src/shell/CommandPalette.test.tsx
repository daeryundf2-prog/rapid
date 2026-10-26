import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { registerCommand, resetCommandRegistry } from "../commands/registry";
import { KEY_MAP } from "../contracts/command";
import { resetAppStore, useAppStore } from "../state/store";
import { CommandPalette } from "./CommandPalette";
import { HelpOverlay } from "./HelpOverlay";

function setup() {
  const opener = document.createElement("button");
  opener.textContent = "opener";
  document.body.append(opener);
  opener.focus();
  const go = vi.fn();
  const theme = vi.fn();
  registerCommand({ id: "navigate.timeline", label: "이동: 타임라인", group: "navigate", run: go });
  registerCommand({ id: "app.theme.toggle", label: "테마 전환", group: "app", run: theme });
  registerCommand({
    id: "case.cancel",
    label: "런 취소",
    group: "case",
    run: vi.fn(),
    disabledReason: () => "실행 중인 런이 아닙니다",
  });
  render(<CommandPalette />);
  act(() => useAppStore.getState().setOverlay("palette", true));
  return { opener, go, theme };
}

const input = () => screen.getByRole("combobox");
const options = () => screen.getAllByRole("option");
const activeOption = () => {
  const id = input().getAttribute("aria-activedescendant");
  return id ? document.getElementById(id) : null;
};

beforeEach(() => {
  resetCommandRegistry();
  window.history.replaceState(null, "", "/v2/");
  resetAppStore({ route: { runId: null, collection: null } });
});

afterEach(() => {
  cleanup();
  resetCommandRegistry();
  document.body.innerHTML = "";
});

describe("CommandPalette", () => {
  it("is a labelled modal dialog with a combobox driving a grouped listbox", () => {
    setup();
    const dialog = screen.getByRole("dialog");
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(dialog.getAttribute("aria-labelledby")).toBeTruthy();
    expect(document.activeElement).toBe(input());
    const listbox = screen.getByRole("listbox");
    expect(input().getAttribute("aria-controls")).toBe(listbox.id);
    // No case open: the 이동 group is hidden (r7 L4, C-G11), the other two stay.
    expect(screen.getAllByRole("group").length).toBe(2);
    expect(activeOption()?.getAttribute("aria-selected")).toBe("true");
  });

  it("fuzzy-filters, moves with arrows and runs with Enter, then returns focus", () => {
    const { opener, theme } = setup();
    fireEvent.change(input(), { target: { value: "테마" } });
    expect(options().map((o) => o.textContent)).toEqual([
      "테마 전환",
      "‘테마’ 전체 검색케이스를 먼저 선택하세요",
    ]);
    fireEvent.change(input(), { target: { value: "" } });
    const first = activeOption()?.textContent;
    fireEvent.keyDown(input(), { key: "ArrowDown" });
    expect(activeOption()?.textContent).not.toBe(first);
    fireEvent.keyDown(input(), { key: "ArrowUp" });
    expect(activeOption()?.textContent).toBe(first);
    fireEvent.change(input(), { target: { value: "theme" } });
    fireEvent.keyDown(input(), { key: "Enter" });
    expect(theme).toHaveBeenCalledTimes(1);
    expect(useAppStore.getState().paletteOpen).toBe(false);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it("keeps disabled commands visible with their reason and does not run them", () => {
    setup();
    fireEvent.change(input(), { target: { value: "런 취소" } });
    const option = options()[0];
    expect(option?.getAttribute("aria-disabled")).toBe("true");
    expect(option?.textContent).toContain("실행 중인 런이 아닙니다");
    fireEvent.keyDown(input(), { key: "Enter" });
    expect(useAppStore.getState().paletteOpen).toBe(true);
  });

  it("offers a global search entry for free text when a case is open", () => {
    useAppStore.getState().navigate({ runId: "r1", collection: "files" });
    setup();
    fireEvent.change(input(), { target: { value: "powershell" } });
    expect(options().at(-1)?.textContent).toContain("‘powershell’ 전체 검색");
    fireEvent.keyDown(input(), { key: "ArrowUp" });
    fireEvent.keyDown(input(), { key: "Enter" });
    expect(window.location.hash).toBe("#/case/r1/explore/search?q=powershell");
  });

  it("closes on Escape and restores focus", () => {
    const { opener } = setup();
    fireEvent.keyDown(input(), { key: "Escape" });
    expect(useAppStore.getState().paletteOpen).toBe(false);
    expect(document.activeElement).toBe(opener);
  });
});

describe("HelpOverlay", () => {
  it("renders every canonical key from the registry", () => {
    registerCommand({ id: "app.help", label: "단축키 도움말", group: "app", shortcut: "?", run: vi.fn() });
    render(<HelpOverlay />);
    act(() => useAppStore.getState().setOverlay("help", true));
    expect(screen.getByRole("dialog").textContent).toContain("단축키 도움말");
    expect(screen.getAllByRole("row").length).toBe(Object.keys(KEY_MAP).length + 1); // header + every KEY_MAP entry
    fireEvent.keyDown(document.activeElement ?? document.body, { key: "Escape" });
    expect(useAppStore.getState().helpOpen).toBe(false);
  });
});
