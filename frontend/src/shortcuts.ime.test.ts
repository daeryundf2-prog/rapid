/** T-035: shortcuts with the Korean IME on — physical-key fallback, never during composition. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { registerCommand, resetCommandRegistry } from "./commands/registry";
import { KEY_MAP } from "./contracts/command";
import { dispatchShortcut, eventToShortcut, physicalKeyChar } from "./shortcuts";
import { resetAppStore } from "./state/store";

function keydown(
  init: KeyboardEventInit & { keyCode?: number },
  target: HTMLElement = document.body,
): KeyboardEvent {
  const { keyCode, ...rest } = init;
  const event = new KeyboardEvent("keydown", { bubbles: true, cancelable: true, ...rest });
  Object.defineProperty(event, "target", { value: target });
  if (keyCode !== undefined) Object.defineProperty(event, "keyCode", { value: keyCode });
  return event;
}

beforeEach(() => {
  resetCommandRegistry();
  resetAppStore();
  document.body.innerHTML = "";
});
afterEach(() => resetCommandRegistry());

describe("physicalKeyChar", () => {
  it("covers Key*, Digit*, Slash and Backquote only", () => {
    expect(physicalKeyChar("KeyR", false)).toBe("R");
    expect(physicalKeyChar("Digit1", false)).toBe("1");
    expect(physicalKeyChar("Digit1", true)).toBe("!");
    expect(physicalKeyChar("Slash", false)).toBe("/");
    expect(physicalKeyChar("Slash", true)).toBe("?");
    expect(physicalKeyChar("Backquote", false)).toBe("`");
    expect(physicalKeyChar("Semicolon", false)).toBeNull();
    expect(physicalKeyChar("Numpad1", false)).toBeNull();
    expect(physicalKeyChar(undefined, false)).toBeNull();
  });
});

describe("eventToShortcut with the Korean IME", () => {
  // The 12 event shapes of the T-035 card.
  it.each([
    ["jamo ㄱ on KeyR", { key: "ㄱ", code: "KeyR" }, "R"],
    ["jamo ㅌ on KeyX", { key: "ㅌ", code: "KeyX" }, "X"],
    ["jamo ㅑ on KeyI", { key: "ㅑ", code: "KeyI" }, "I"],
    ["jamo ㅠ on KeyB", { key: "ㅠ", code: "KeyB" }, "B"],
    ["jamo ㅏ on KeyK", { key: "ㅏ", code: "KeyK" }, "K"],
    ["Process on KeyT", { key: "Process", code: "KeyT", keyCode: 229 }, "T"],
    ["Process on KeyF", { key: "Process", code: "KeyF", keyCode: 229 }, "F"],
    [
      "Process + Shift on Slash",
      { key: "Process", code: "Slash", shiftKey: true, keyCode: 229 },
      KEY_MAP.help,
    ],
    ["Process on Slash", { key: "Process", code: "Slash", keyCode: 229 }, KEY_MAP.gridFilter],
    ["Process on Backquote", { key: "Process", code: "Backquote", keyCode: 229 }, KEY_MAP.classicSplit],
    ["Process on Digit1", { key: "Process", code: "Digit1", keyCode: 229 }, "1"],
    [
      "Process + Alt+Shift on Digit2",
      { key: "Process", code: "Digit2", altKey: true, shiftKey: true },
      "Alt+Shift+2",
    ],
  ] as const)("%s → %s", (_name, init, expected) => {
    expect(eventToShortcut(keydown({ ...init }))).toBe(expected);
  });

  it("jamo with Shift keeps Shift on the letter (ㄲ on Shift+KeyR)", () => {
    expect(eventToShortcut(keydown({ key: "ㄲ", code: "KeyR", shiftKey: true }))).toBe("Shift+R");
    expect(eventToShortcut(keydown({ key: "ㄹ", code: "KeyF", shiftKey: true }))).toBe(KEY_MAP.familyView);
  });

  it("Latin keys are untouched (no fallback when key is already ASCII)", () => {
    expect(eventToShortcut(keydown({ key: "r", code: "KeyR" }))).toBe("R");
    expect(eventToShortcut(keydown({ key: "/", code: "Slash" }))).toBe("/");
    // An AZERTY "a" on the physical Q key stays "A": the fallback is for non-Latin keys only.
    expect(eventToShortcut(keydown({ key: "a", code: "KeyQ" }))).toBe("A");
  });

  it("Process outside the fallback range binds nothing", () => {
    expect(eventToShortcut(keydown({ key: "Process", code: "Semicolon" }))).toBeNull();
    expect(eventToShortcut(keydown({ key: "Process", code: "" }))).toBeNull();
  });

  it("returns null while composing", () => {
    expect(eventToShortcut(keydown({ key: "ㄱ", code: "KeyR", isComposing: true }))).toBeNull();
    expect(
      eventToShortcut(keydown({ key: "Process", code: "KeyK", ctrlKey: true, isComposing: true })),
    ).toBeNull();
  });
});

describe("dispatchShortcut with the Korean IME", () => {
  function bind(shortcut: string) {
    const run = vi.fn();
    registerCommand({ id: `test.${shortcut}`, label: shortcut, group: "app", shortcut, run });
    return run;
  }

  it("fires R, ?, / and ` from IME keys on the page", () => {
    const relevant = bind(KEY_MAP.markRelevant);
    const help = bind(KEY_MAP.help);
    const filter = bind(KEY_MAP.gridFilter);
    const split = bind(KEY_MAP.classicSplit);
    expect(dispatchShortcut(keydown({ key: "ㄱ", code: "KeyR" }))).toBe(true);
    expect(dispatchShortcut(keydown({ key: "Process", code: "Slash", shiftKey: true, keyCode: 229 }))).toBe(
      true,
    );
    expect(dispatchShortcut(keydown({ key: "Process", code: "Slash", keyCode: 229 }))).toBe(true);
    expect(dispatchShortcut(keydown({ key: "Process", code: "Backquote", keyCode: 229 }))).toBe(true);
    expect(relevant).toHaveBeenCalledTimes(1);
    expect(help).toHaveBeenCalledTimes(1);
    expect(filter).toHaveBeenCalledTimes(1);
    expect(split).toHaveBeenCalledTimes(1);
  });

  it("fires nothing during composition, nor on an IME key (229) inside a text field", () => {
    const relevant = bind(KEY_MAP.markRelevant);
    const palette = bind(KEY_MAP.palette);
    const input = document.createElement("input");
    document.body.append(input);
    // Composing on the page (e.g. a contenteditable-less IME session): ignored.
    expect(dispatchShortcut(keydown({ key: "ㄱ", code: "KeyR", isComposing: true, keyCode: 229 }))).toBe(
      false,
    );
    // First key of a composition in a text field: isComposing is still false, keyCode is 229.
    expect(dispatchShortcut(keydown({ key: "Process", code: "KeyR", keyCode: 229 }, input))).toBe(false);
    expect(
      dispatchShortcut(keydown({ key: "Process", code: "KeyK", ctrlKey: true, keyCode: 229 }, input)),
    ).toBe(false);
    expect(dispatchShortcut(keydown({ key: "ㄱ", code: "KeyR", isComposing: true }, input))).toBe(false);
    expect(relevant).not.toHaveBeenCalled();
    expect(palette).not.toHaveBeenCalled();
    // Ctrl+K without the IME still works from a text field.
    expect(dispatchShortcut(keydown({ key: "k", code: "KeyK", ctrlKey: true }, input))).toBe(true);
    expect(palette).toHaveBeenCalledTimes(1);
  });
});
