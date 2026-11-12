import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getCommands, registerCommand, resetCommandRegistry } from "../commands/registry";
import { type Command, KEY_MAP } from "../contracts/command";
import { resetAppStore, useAppStore } from "../state/store";
import { buildPaletteGroups, CATEGORY_PREFIX, CommandPalette, PALETTE_EMPTY_LIMIT } from "./CommandPalette";
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
    // No case open: the 이동 group is hidden (r7 L4, C-G11) and commands that cannot run stay
    // out of the plain list (C-G11 remainder) — only the group with a runnable command is left.
    expect(screen.getAllByRole("group").length).toBe(1);
    expect(activeOption()?.getAttribute("aria-selected")).toBe("true");
  });

  it("fuzzy-filters, moves with arrows and runs with Enter, then returns focus", () => {
    const { opener, theme } = setup();
    fireEvent.change(input(), { target: { value: "테마" } });
    expect(options().map((o) => o.textContent)).toEqual([
      "테마 전환",
      "‘테마’ 전체 검색케이스를 먼저 선택하세요",
    ]);
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

describe("CommandPalette: executable commands only (T-035)", () => {
  /** A case-open registry shaped like the real one: many disabled entries and hundreds of 이동: moves. */
  function registerMany() {
    for (let i = 0; i < 100; i += 1) {
      registerCommand({ id: `grid.ok.${i}`, label: `그리드 동작 ${i}`, group: "grid", run: vi.fn() });
    }
    for (let i = 0; i < 300; i += 1) {
      registerCommand({
        id: `review.off.${i}`,
        label: `리뷰 동작 ${i}`,
        group: "review",
        run: vi.fn(),
        disabledReason: () => "선택한 행이 없습니다",
      });
    }
    for (let i = 0; i < 150; i += 1) {
      registerCommand({ id: `tree.goto.n${i}`, label: `이동: 노드 ${i}`, group: "navigate", run: vi.fn() });
    }
    registerCommand({ id: "stage.review", label: "단계: 검토", group: "navigate", run: vi.fn() });
  }

  beforeEach(() => {
    useAppStore.getState().navigate({ runId: "r1", collection: "files" });
  });

  it("empty input lists no disabled entry, at most 60, and no category moves", () => {
    registerMany();
    render(<CommandPalette />);
    act(() => useAppStore.getState().setOverlay("palette", true));
    const shown = options();
    expect(shown.length).toBeLessThanOrEqual(PALETTE_EMPTY_LIMIT);
    expect(shown.length).toBeGreaterThan(0);
    expect(shown.filter((o) => o.getAttribute("aria-disabled") === "true")).toHaveLength(0);
    expect(shown.some((o) => o.textContent?.startsWith(CATEGORY_PREFIX))).toBe(false);
    // Stage moves are actions, not category moves: still listed.
    expect(shown.some((o) => o.textContent?.includes("단계: 검토"))).toBe(true);
  });

  it("category moves appear only behind the 이동: prefix", () => {
    registerMany();
    render(<CommandPalette />);
    act(() => useAppStore.getState().setOverlay("palette", true));
    fireEvent.change(input(), { target: { value: "노드 12" } });
    expect(options().some((o) => o.textContent?.startsWith(CATEGORY_PREFIX))).toBe(false);
    fireEvent.change(input(), { target: { value: "이동: 노드 12" } });
    const moves = options().filter(
      (o) => o.getAttribute("role") === "option" && o.textContent?.startsWith("이동:"),
    );
    expect(moves.length).toBeGreaterThan(0);
    expect(moves[0]?.textContent).toBe("이동: 노드 12");
    // In 이동: mode nothing but moves (and the free-text search entry) is listed.
    expect(options().filter((o) => o.textContent?.includes("그리드 동작"))).toHaveLength(0);
  });

  it("typing a disabled command's name still finds it with its reason, after runnable matches", () => {
    registerMany();
    registerCommand({ id: "review.ok.x", label: "리뷰 동작 실행됨", group: "review", run: vi.fn() });
    render(<CommandPalette />);
    act(() => useAppStore.getState().setOverlay("palette", true));
    fireEvent.change(input(), { target: { value: "리뷰 동작" } });
    const review = options().filter((o) => o.textContent?.startsWith("리뷰 동작"));
    expect(review[0]?.getAttribute("aria-disabled")).toBeNull();
    expect(review[1]?.getAttribute("aria-disabled")).toBe("true");
    expect(review[1]?.textContent).toContain("선택한 행이 없습니다");
  });

  it("모든 명령 lists disabled commands too, each with its Korean reason", () => {
    registerMany();
    render(<CommandPalette />);
    act(() => useAppStore.getState().setOverlay("palette", true));
    fireEvent.click(screen.getByRole("checkbox", { name: "모든 명령" }));
    const disabled = options().filter((o) => o.getAttribute("aria-disabled") === "true");
    expect(disabled).toHaveLength(300);
    expect(disabled.every((o) => o.textContent?.includes("선택한 행이 없습니다"))).toBe(true);
    expect(options().some((o) => o.textContent?.startsWith(CATEGORY_PREFIX))).toBe(false);
  });

  it("buildPaletteGroups counts: 401 commands + 150 moves → ≤ 60 runnable on empty input", () => {
    registerMany();
    const all = getCommands();
    const reasonOf = (c: Command) => c.disabledReason?.({} as never) ?? undefined;
    const empty = buildPaletteGroups(all, "", reasonOf).flatMap((g) => g.items);
    expect(empty.length).toBe(PALETTE_EMPTY_LIMIT);
    expect(empty.filter((i) => i.disabledReason)).toHaveLength(0);
    const everything = buildPaletteGroups(all, "", reasonOf, [], { showAll: true }).flatMap((g) => g.items);
    expect(everything.length).toBe(100 + 300 + 1);
    const moves = buildPaletteGroups(all, "이동:", reasonOf).flatMap((g) => g.items);
    expect(moves.length).toBe(150);
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
