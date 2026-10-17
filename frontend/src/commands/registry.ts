/**
 * Command registry (contracts/command.ts). Every user-visible action is a
 * Command; the palette, the key map, toolbar buttons and the help overlay are
 * all views of this registry. A command either runs or reports a Korean
 * `disabledReason` (shown in the tooltip and announced) — never a silent no-op.
 *
 * Shortcuts: a command's `shortcut` must be one of the canonical keys in
 * KEY_MAP (U5) and no two commands may hold the same key; registering a
 * conflicting or non-canonical shortcut throws.
 */

import { useMemo, useSyncExternalStore } from "react";
import { useShallow } from "zustand/react/shallow";
import { announce } from "../a11y";
import { type Command, type CommandContext, type CommandGroup, KEY_MAP } from "../contracts/command";
import { currentRun, isRunActive } from "../state/slices/runs";
import { type AppState, useAppStore } from "../state/store";

export type CommandResult = { ok: true } | { ok: false; reason: string };

export class CommandRegistrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CommandRegistrationError";
  }
}

// --- shortcut normalisation ----------------------------------------------

const MODIFIER_ORDER = ["Ctrl", "Alt", "Shift"] as const;
const KEY_ALIASES: Record<string, string> = {
  esc: "Escape",
  escape: "Escape",
  " ": "Space",
  space: "Space",
  spacebar: "Space",
  enter: "Enter",
  return: "Enter",
  left: "ArrowLeft",
  right: "ArrowRight",
  up: "ArrowUp",
  down: "ArrowDown",
  arrowleft: "ArrowLeft",
  arrowright: "ArrowRight",
  arrowup: "ArrowUp",
  arrowdown: "ArrowDown",
};

function normalizeKeyName(key: string): string {
  const alias = KEY_ALIASES[key.toLowerCase()];
  if (alias) return alias;
  if (key.length === 1) return key.toUpperCase();
  return key;
}

/** "ctrl+k" → "Ctrl+K", "meta+k" → "Ctrl+K", "alt+left" → "Alt+ArrowLeft". */
export function normalizeShortcut(shortcut: string): string {
  const parts = shortcut.split("+");
  // "+" itself as a key ("Ctrl++") leaves an empty trailing part.
  const rawKey = shortcut.endsWith("++") ? "+" : (parts.pop() ?? "");
  const modifiers = new Set<string>();
  for (const part of parts) {
    const p = part.trim().toLowerCase();
    if (p === "ctrl" || p === "control" || p === "meta" || p === "cmd") modifiers.add("Ctrl");
    else if (p === "alt" || p === "option") modifiers.add("Alt");
    else if (p === "shift") modifiers.add("Shift");
  }
  const ordered = MODIFIER_ORDER.filter((m) => modifiers.has(m));
  return [...ordered, normalizeKeyName(rawKey.trim() || rawKey)].join("+");
}

/** KEY_MAP values, with the "1-5" range expanded to "1".."5". */
export const CANONICAL_KEYS: ReadonlySet<string> = new Set(
  Object.values(KEY_MAP).flatMap((value) => {
    const range = /^(\d)-(\d)$/.exec(value);
    if (!range) return [normalizeShortcut(value)];
    const out: string[] = [];
    for (let n = Number(range[1]); n <= Number(range[2]); n++) out.push(String(n));
    return out;
  }),
);

// --- registry --------------------------------------------------------------

const commands = new Map<string, Command>();
const shortcutOwners = new Map<string, string>();
const listeners = new Set<() => void>();
let snapshot: readonly Command[] = [];

function emit(): void {
  snapshot = Array.from(commands.values());
  for (const listener of listeners) listener();
}

export function subscribeCommands(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function getCommandsSnapshot(): readonly Command[] {
  return snapshot;
}

/** Register a command; returns its unregister function. Throws on id or shortcut conflicts. */
export function registerCommand(command: Command): () => void {
  if (commands.has(command.id)) {
    throw new CommandRegistrationError(`명령 id 중복: ${command.id}`);
  }
  let key: string | undefined;
  if (command.shortcut) {
    key = normalizeShortcut(command.shortcut);
    if (!CANONICAL_KEYS.has(key)) {
      throw new CommandRegistrationError(`KEY_MAP에 없는 단축키입니다: ${command.shortcut} (${command.id})`);
    }
    const owner = shortcutOwners.get(key);
    if (owner) {
      throw new CommandRegistrationError(`단축키 ${key}는 이미 ${owner}에 묶여 있습니다 (${command.id})`);
    }
    shortcutOwners.set(key, command.id);
  }
  const stored: Command = key ? { ...command, shortcut: key } : command;
  commands.set(command.id, stored);
  emit();
  return () => {
    if (commands.get(command.id) !== stored) return;
    commands.delete(command.id);
    if (key && shortcutOwners.get(key) === command.id) shortcutOwners.delete(key);
    emit();
  };
}

export function registerCommands(list: readonly Command[]): () => void {
  const undo: Array<() => void> = [];
  try {
    for (const command of list) undo.push(registerCommand(command));
  } catch (error) {
    for (const fn of undo.reverse()) fn();
    throw error;
  }
  return () => {
    for (const fn of undo.reverse()) fn();
  };
}

/**
 * Change a registered command's label (palette text) in place, e.g. a digit tag key once the
 * case's tags load ("태그 단축키 7 (DLP 유출 후보)"). Unknown ids are ignored.
 */
export function relabelCommand(id: string, label: string): void {
  const command = commands.get(id);
  if (!command || command.label === label) return;
  command.label = label;
  emit();
}

export function getCommand(id: string): Command | undefined {
  return commands.get(id);
}

export function getCommands(group?: CommandGroup): Command[] {
  const all = Array.from(commands.values());
  return group ? all.filter((c) => c.group === group) : all;
}

/** The command bound to a normalised key, if any. */
export function commandForShortcut(key: string): Command | undefined {
  const id = shortcutOwners.get(normalizeShortcut(key));
  return id ? commands.get(id) : undefined;
}

/** Tests only. */
export function resetCommandRegistry(): void {
  commands.clear();
  shortcutOwners.clear();
  emit();
}

// --- context + running -----------------------------------------------------

export function commandContextFrom(state: AppState): CommandContext {
  return {
    runId: state.route.runId,
    collection: state.route.collection,
    selectedRowKeys: state.selectedRowKeys,
    focusedRowKey: state.focusedRowKey,
    viewerHasTarget: state.viewerTarget !== null,
    runIsActive: isRunActive(currentRun(state)),
  };
}

export function getCommandContext(): CommandContext {
  return commandContextFrom(useAppStore.getState());
}

export function disabledReasonOf(command: Command, ctx: CommandContext): string | undefined {
  try {
    return command.disabledReason?.(ctx) || undefined;
  } catch {
    return "지금은 실행할 수 없습니다";
  }
}

function errorText(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  return String(error);
}

export interface RunCommandOptions {
  /** Do not announce a disabled reason (used for Esc with nothing to close). */
  silentWhenDisabled?: boolean;
  ctx?: CommandContext;
}

/** Run a command by id. Disabled → reason announced + returned; failure → error announced. */
export async function runCommand(id: string, options: RunCommandOptions = {}): Promise<CommandResult> {
  const command = commands.get(id);
  const store = useAppStore.getState();
  if (!command) {
    const reason = `등록되지 않은 명령입니다: ${id}`;
    store.showNotice(reason, "error");
    announce(reason);
    return { ok: false, reason };
  }
  const ctx = options.ctx ?? getCommandContext();
  const reason = disabledReasonOf(command, ctx);
  if (reason) {
    if (!options.silentWhenDisabled) {
      store.showNotice(`${command.label}: ${reason}`);
      announce(`${command.label}: ${reason}`);
    }
    return { ok: false, reason };
  }
  try {
    await command.run(ctx);
    return { ok: true };
  } catch (error) {
    const message = `${command.label} 실패: ${errorText(error)}`;
    store.showNotice(message, "error");
    announce(message, { politeness: "assertive" });
    return { ok: false, reason: message };
  }
}

// --- hooks -----------------------------------------------------------------

/** Live command context (re-renders when route, selection, viewer or run state changes). */
export function useCommandContext(): CommandContext {
  return useAppStore(useShallow(commandContextFrom));
}

/** All registered commands, optionally of one group (re-renders on (un)registration). */
export function useCommands(group?: CommandGroup): Command[] {
  const all = useSyncExternalStore(subscribeCommands, getCommandsSnapshot, getCommandsSnapshot);
  return useMemo(() => (group ? all.filter((c) => c.group === group) : [...all]), [all, group]);
}

export interface CommandState {
  command: Command | undefined;
  /** Korean reason when the command cannot run now (also when it is not registered). */
  disabledReason: string | undefined;
  run: () => Promise<CommandResult>;
}

/** A button's view of one command. */
export function useCommandState(id: string): CommandState {
  const all = useSyncExternalStore(subscribeCommands, getCommandsSnapshot, getCommandsSnapshot);
  const ctx = useCommandContext();
  const command = all.find((c) => c.id === id);
  const disabledReason = command ? disabledReasonOf(command, ctx) : "아직 준비되지 않은 기능입니다";
  return { command, disabledReason, run: () => runCommand(id) };
}
