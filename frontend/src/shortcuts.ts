/**
 * The single keyboard dispatcher (plan U5). One window keydown listener maps a
 * normalised key ("Ctrl+K", "J", "?", "Alt+ArrowLeft") to the one command
 * that owns it in the registry. Keys are bound by giving a command a
 * `shortcut` from KEY_MAP; the registry rejects a second binding, so a key can
 * never mean two things. Components must not add their own global keydown
 * listeners for KEY_MAP keys — register a command instead.
 *
 * Local keys inside composite widgets (arrows in a tablist / tree / grid,
 * Enter on a button) stay with the widget: the dispatcher ignores plain keys
 * in text fields and in modal dialogs, and Enter/Space on interactive controls.
 */

import { useEffect } from "react";
import { isTextEntry } from "./a11y";
import { commandForShortcut, getCommands, normalizeShortcut, runCommand } from "./commands/registry";
import { type Command, KEY_MAP } from "./contracts/command";

const MODIFIER_KEYS = new Set([
  "Control",
  "Alt",
  "Shift",
  "Meta",
  "AltGraph",
  "CapsLock",
  "Dead",
  "Unidentified",
]);

const INTERACTIVE_ROLES = new Set([
  "button",
  "link",
  "option",
  "tab",
  "treeitem",
  "menuitem",
  "menuitemcheckbox",
  "menuitemradio",
  "checkbox",
  "switch",
  "radio",
  "combobox",
  "slider",
  "spinbutton",
]);

function isInteractiveTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (/^(BUTTON|A|SUMMARY|INPUT|SELECT|TEXTAREA)$/.test(target.tagName)) return true;
  const role = target.getAttribute("role");
  return role !== null && INTERACTIVE_ROLES.has(role);
}

/** Normalise a KeyboardEvent to the registry's shortcut notation; null for bare modifiers / IME. */
export function eventToShortcut(
  event: Pick<KeyboardEvent, "key" | "code" | "ctrlKey" | "metaKey" | "altKey" | "shiftKey" | "isComposing">,
): string | null {
  if (event.isComposing) return null;
  let key = event.key;
  if (!key || MODIFIER_KEYS.has(key)) return null;
  // Korean (or any non-Latin) layout: letters arrive as jamo / "Process"; fall back to the physical key.
  const physical = /^Key([A-Z])$/.exec(event.code ?? "");
  if (physical?.[1] && (key === "Process" || (key.length === 1 && !/^[\x20-\x7e]$/.test(key)))) {
    key = physical[1];
  }
  if (key === "Process") return null;
  // Alt+Shift+1 arrives as key "!" (layout-dependent): with a command modifier, name the digit row by its physical key.
  const digit = /^Digit(\d)$/.exec(event.code ?? "");
  if (digit?.[1] && event.shiftKey && (event.altKey || event.ctrlKey || event.metaKey) && !/^\d$/.test(key)) {
    key = digit[1];
  }
  // Alt/Ctrl+digit shortcuts (stages, views) are the digit ROW only: Alt+NumPad digits are
  // Windows Alt-codes, so a numpad digit keeps its physical name ("Alt+Numpad1" binds nothing).
  const commandModified = event.altKey || event.ctrlKey || event.metaKey;
  if (commandModified && /^\d$/.test(key) && event.code && !event.code.startsWith("Digit")) {
    key = event.code;
  }
  const shiftedDigit = event.shiftKey && /^\d$/.test(key) && commandModified;
  const isLetter = key.length === 1 && /[a-z]/i.test(key);
  const isNamed = key.length > 1;
  const parts: string[] = [];
  if (event.ctrlKey || event.metaKey) parts.push("Ctrl");
  if (event.altKey) parts.push("Alt");
  // Shift is part of the key for punctuation ("?" is Shift+/), explicit for letters and named keys.
  if (event.shiftKey && (isLetter || isNamed || shiftedDigit)) parts.push("Shift");
  if (key === " ") key = "Space";
  parts.push(key.length === 1 ? key.toUpperCase() : key === "Esc" ? "Escape" : key);
  return parts.join("+");
}

function hasCommandModifier(shortcut: string): boolean {
  return shortcut.startsWith("Ctrl+") || shortcut.startsWith("Alt+");
}

/**
 * Global keys that still act while focus is inside a modal dialog: Escape (close) and
 * Ctrl+K (the palette toggles itself closed). Everything else — stage switches (Alt+1~5),
 * view switches, viewer history — would act on the page behind the dialog.
 */
const MODAL_SAFE_SHORTCUTS: ReadonlySet<string> = new Set(["Escape", "Ctrl+K"]);

/**
 * Route one keydown to its command. Returns true when a command claimed the
 * key (the event is then preventDefault-ed).
 */
export function dispatchShortcut(event: KeyboardEvent): boolean {
  if (event.defaultPrevented) return false;
  const shortcut = eventToShortcut(event);
  if (!shortcut) return false;
  const command = commandForShortcut(shortcut);
  if (!command) return false;

  const target = event.target;
  const modified = hasCommandModifier(shortcut);
  if (
    !MODAL_SAFE_SHORTCUTS.has(shortcut) &&
    target instanceof Element &&
    target.closest('[aria-modal="true"]')
  ) {
    return false;
  }
  if (!modified && shortcut !== "Escape") {
    if (isTextEntry(target)) return false;
    if ((shortcut === "Enter" || shortcut === "Space") && isInteractiveTarget(target)) return false;
  }

  event.preventDefault();
  void runCommand(command.id, { silentWhenDisabled: shortcut === "Escape" });
  return true;
}

let installed = 0;
function onWindowKeyDown(event: KeyboardEvent): void {
  dispatchShortcut(event);
}

/** Install the central dispatcher (once, at the app root). Safe under StrictMode. */
export function useShortcuts(): void {
  useEffect(() => {
    if (installed++ === 0) window.addEventListener("keydown", onWindowKeyDown);
    return () => {
      if (--installed === 0) window.removeEventListener("keydown", onWindowKeyDown);
    };
  }, []);
}

/** Korean description of each canonical key (help overlay). */
export const KEY_DESCRIPTIONS: Record<keyof typeof KEY_MAP, string> = {
  palette: "명령 팔레트 열기",
  gridFilter: "그리드 필터로 이동",
  rowDown: "다음 행",
  rowUp: "이전 행",
  openViewer: "뷰어로 이동 (좁은 화면에서는 뷰어 열기)",
  toggleSelect: "행 선택/해제",
  markRelevant: "관련 있음 표시",
  markExcluded: "제외 표시",
  markNeedsReview: "재검토 표시",
  bookmark: "북마크",
  priority1to5: "우선순위 태그 1–5",
  viewerBack: "뷰어 이전 항목",
  viewerForward: "뷰어 다음 항목",
  help: "단축키 도움말",
  close: "닫기",
  viewColumns: "열 보기",
  viewThumbnails: "썸네일 보기",
  viewChat: "대화 보기",
  viewHistogram: "히스토그램 보기",
  stageIntake: "단계: 접수",
  stageProcess: "단계: 처리",
  stageExplore: "단계: 탐색",
  stageReview: "단계: 검토",
  stageReport: "단계: 보고",
};

/** Apple platform (review #14): only there does Ctrl+K read as the ⌘ glyph. */
export function isMacPlatform(
  platform: string = typeof navigator === "undefined" ? "" : navigator.platform,
): boolean {
  return /^(Mac|iPhone|iPad|iPod)/i.test(platform);
}

/** Human-readable key label ("Ctrl+K" → "Ctrl K", "⌘K" on a Mac; arrows as glyphs). */
export function keyLabel(shortcut: string, mac: boolean = isMacPlatform()): string {
  if (mac && shortcut.startsWith("Ctrl+")) return `⌘${keyLabel(shortcut.slice(5), false)}`;
  return shortcut
    .replace("ArrowLeft", "←")
    .replace("ArrowRight", "→")
    .replace("ArrowUp", "↑")
    .replace("ArrowDown", "↓")
    .replace("Escape", "Esc")
    .replace("Space", "스페이스")
    .split("+")
    .join(" ");
}

export interface KeyBindingRow {
  name: keyof typeof KEY_MAP;
  shortcut: string;
  description: string;
  /** Commands currently bound to this key (several only for the 1–5 range). */
  commands: Command[];
}

/** One row per KEY_MAP entry, with the commands currently bound (help overlay). */
export function keyBindingRows(): KeyBindingRow[] {
  const all = getCommands();
  return (Object.keys(KEY_MAP) as Array<keyof typeof KEY_MAP>).map((name) => {
    const shortcut = KEY_MAP[name];
    const range = /^(\d)-(\d)$/.exec(shortcut);
    const bound = range
      ? all.filter(
          (c) =>
            c.shortcut &&
            /^\d$/.test(c.shortcut) &&
            c.shortcut >= (range[1] ?? "") &&
            c.shortcut <= (range[2] ?? ""),
        )
      : all.filter((c) => c.shortcut === normalizeShortcut(shortcut));
    return { name, shortcut, description: KEY_DESCRIPTIONS[name], commands: bound };
  });
}
