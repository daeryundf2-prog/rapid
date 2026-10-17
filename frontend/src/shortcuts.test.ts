import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { registerCommand, resetCommandRegistry } from "./commands/registry";
import { KEY_MAP } from "./contracts/command";
import { dispatchShortcut, eventToShortcut, keyBindingRows } from "./shortcuts";
import { resetAppStore } from "./state/store";

function keydown(init: KeyboardEventInit, target: HTMLElement = document.body): KeyboardEvent {
  const event = new KeyboardEvent("keydown", { bubbles: true, cancelable: true, ...init });
  Object.defineProperty(event, "target", { value: target });
  return event;
}

beforeEach(() => {
  resetCommandRegistry();
  resetAppStore();
  document.body.innerHTML = "";
});
afterEach(() => resetCommandRegistry());

describe("eventToShortcut", () => {
  it("normalises modifiers and printable keys", () => {
    expect(eventToShortcut(keydown({ key: "k", ctrlKey: true }))).toBe("Ctrl+K");
    expect(eventToShortcut(keydown({ key: "k", metaKey: true }))).toBe("Ctrl+K");
    expect(eventToShortcut(keydown({ key: "j" }))).toBe("J");
    expect(eventToShortcut(keydown({ key: "J", shiftKey: true }))).toBe("Shift+J");
    expect(eventToShortcut(keydown({ key: "?", shiftKey: true }))).toBe("?");
    expect(eventToShortcut(keydown({ key: " " }))).toBe("Space");
    expect(eventToShortcut(keydown({ key: "ArrowLeft", altKey: true }))).toBe("Alt+ArrowLeft");
    expect(eventToShortcut(keydown({ key: "Shift", shiftKey: true }))).toBeNull();
  });

  it("falls back to the physical key on a Korean layout", () => {
    expect(eventToShortcut(keydown({ key: "ㅓ", code: "KeyJ" }))).toBe("J");
    expect(eventToShortcut(keydown({ key: "Process", code: "KeyR" }))).toBe("R");
  });
});

describe("dispatchShortcut", () => {
  it("routes a key to its single command and prevents the default", () => {
    const run = vi.fn();
    registerCommand({ id: "t.help", label: "도움말", group: "app", shortcut: KEY_MAP.help, run });
    const event = keydown({ key: "?", shiftKey: true });
    expect(dispatchShortcut(event)).toBe(true);
    expect(event.defaultPrevented).toBe(true);
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("never binds a key twice", () => {
    registerCommand({ id: "a", label: "A", group: "grid", shortcut: "J", run: vi.fn() });
    expect(() =>
      registerCommand({ id: "b", label: "B", group: "grid", shortcut: "j", run: vi.fn() }),
    ).toThrow();
  });

  it("leaves plain keys to text fields, dialogs and focused buttons; Ctrl combos still work", () => {
    const run = vi.fn();
    const palette = vi.fn();
    registerCommand({ id: "t.r", label: "관련", group: "review", shortcut: "R", run });
    registerCommand({ id: "t.enter", label: "뷰어", group: "viewer", shortcut: "Enter", run });
    registerCommand({ id: "t.palette", label: "팔레트", group: "app", shortcut: "Ctrl+K", run: palette });
    const input = document.createElement("input");
    const button = document.createElement("button");
    const dialog = document.createElement("div");
    dialog.setAttribute("aria-modal", "true");
    const inside = document.createElement("div");
    dialog.append(inside);
    document.body.append(input, button, dialog);

    expect(dispatchShortcut(keydown({ key: "r" }, input))).toBe(false);
    expect(dispatchShortcut(keydown({ key: "r" }, inside))).toBe(false);
    expect(dispatchShortcut(keydown({ key: "Enter" }, button))).toBe(false);
    expect(run).not.toHaveBeenCalled();
    expect(dispatchShortcut(keydown({ key: "k", ctrlKey: true }, input))).toBe(true);
    expect(palette).toHaveBeenCalledTimes(1);

    const row = document.createElement("div");
    row.setAttribute("role", "row");
    document.body.append(row);
    expect(dispatchShortcut(keydown({ key: "Enter" }, row))).toBe(true);
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("ignores events a widget already handled", () => {
    const run = vi.fn();
    registerCommand({ id: "t.j", label: "다음", group: "grid", shortcut: "J", run });
    const event = keydown({ key: "j" });
    event.preventDefault();
    expect(dispatchShortcut(event)).toBe(false);
    expect(run).not.toHaveBeenCalled();
  });
});

describe("help rows", () => {
  it("lists every KEY_MAP entry with its bound commands", () => {
    registerCommand({ id: "p1", label: "우선순위 1", group: "review", shortcut: "1", run: vi.fn() });
    registerCommand({ id: "h", label: "도움말", group: "app", shortcut: "?", run: vi.fn() });
    const rows = keyBindingRows();
    expect(rows).toHaveLength(Object.keys(KEY_MAP).length);
    expect(rows.find((r) => r.name === "tagShortcuts")?.commands.map((c) => c.id)).toEqual(["p1"]);
    // One digit row for the main window (tag keys 1–9); the old 우선순위 1–5 row is gone.
    expect(rows.map((r) => r.name)).not.toContain("priority1to5");
    expect(rows.filter((r) => /^\d-\d$/.test(r.shortcut)).map((r) => r.name)).toEqual([
      "viewerModes",
      "tagShortcuts",
    ]);
    expect(rows.find((r) => r.name === "help")?.commands.map((c) => c.id)).toEqual(["h"]);
    expect(rows.find((r) => r.name === "rowDown")?.commands).toEqual([]);
  });
});
