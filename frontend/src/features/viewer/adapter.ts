/**
 * Viewer ↔ shell adapter (stream S2 → S1 wiring point).
 *
 * The viewer keeps a tiny local store (its tests drive it directly). In the
 * app, src/app/viewerBridge.ts syncs it with the S1 store (target, `mode=`,
 * focus requests), and the command functions below delegate to the S1
 * registry so viewer.back/forward (Alt ←/→) reach the single key map:
 *
 *   useViewerTarget(): ViewerTarget | null          — selected row's target (store `viewer.target`)
 *   setViewerTarget(target: ViewerTarget | null)    — grid/tree publish; viewer history replays
 *   useViewerFocusRequest(): number                  — increments when the grid opens the viewer with Enter
 *   requestViewerFocus(): void                       — what S1's Enter handler calls
 *   registerCommand(cmd: Command): () => void        — command registry (returns unregister)
 *   getCommand(id: string): Command | undefined      — registry lookup
 *   useCommandContext(): CommandContext              — current palette/keymap context
 *   useViewerRowContext(): GridRow | null            — selected GridRow (review status/tags/provenance for MetaView)
 *   useHighlightTerms(): string[]                    — route `q=` keywords for Document/Source highlight
 *   useViewerRouteMode(): { mode, setMode }          — URL `mode=` (restore + mirror the chosen tab)
 *
 * S1 mapping (src/state/hooks.ts, src/commands, src/shell/slots.tsx as landed):
 *   useViewerTarget()        → useViewerTarget().target            (state/hooks)
 *   setViewerTarget(t)       → useAppStore.getState().setViewerTarget(t)
 *   useViewerRouteMode()     → { mode, setMode } of useViewerTarget() (state/hooks)
 *   useHighlightTerms()      → useRoute().route.q split on whitespace
 *   registerCommand/getCommand/useCommandContext → src/commands (same names)
 *   useViewerFocusRequest()  → optional: S1's focusViewer() already focuses
 *                               `[data-viewer-focus]`, which the selected mode tab carries
 *   <Viewer /> registers as registerSlot("viewer", Viewer)
 *
 * Navigation the viewer cannot perform itself (e.g. "같은 출처의 다른 행")
 * goes through `dispatchCommand(id)`: it runs the registered command when
 * one exists (S3/S4 register `navigate.rows-for-source` and read the source
 * path from `useViewerTarget`), and always emits a `rapidtriage:command`
 * CustomEvent with `{ id, target }` for listeners outside the registry.
 */

import { useMemo, useSyncExternalStore } from "react";
import {
  getCommand as getShellCommand,
  registerCommand as registerShellCommand,
  useCommandContext as useShellCommandContext,
  useCommands as useShellCommands,
} from "../../commands/registry";
import type { GridRow } from "../../contracts/collection";
import type { Command, CommandContext } from "../../contracts/command";
import type { ViewerMode, ViewerTarget } from "../../contracts/viewer";
import { useAppStore } from "../../state/store";
import { resetViewerSession } from "./session";

// ---------------------------------------------------------------------------
// Tiny external store (no dependency on S1's zustand slices).
// ---------------------------------------------------------------------------

interface AdapterState {
  target: ViewerTarget | null;
  focusSeq: number;
  row: GridRow | null;
  commandsVersion: number;
  routeMode: ViewerMode | undefined;
}

let state: AdapterState = { target: null, focusSeq: 0, row: null, commandsVersion: 0, routeMode: undefined };
const listeners = new Set<() => void>();
const commands = new Map<string, Command>();

function setState(patch: Partial<AdapterState>): void {
  state = { ...state, ...patch };
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** S1 bridge: observe target / mode / focus changes made inside the viewer. */
export function subscribeViewerAdapter(listener: () => void): () => void {
  return subscribe(listener);
}

function useAdapter<T>(select: (s: AdapterState) => T): T {
  return useSyncExternalStore(
    subscribe,
    () => select(state),
    () => select(state),
  );
}

// ---------------------------------------------------------------------------
// Target + focus
// ---------------------------------------------------------------------------

export function useViewerTarget(): ViewerTarget | null {
  return useAdapter((s) => s.target);
}

export function getViewerTarget(): ViewerTarget | null {
  return state.target;
}

function rowMatches(row: GridRow | null, target: ViewerTarget | null): boolean {
  return Boolean(
    row &&
      target &&
      row.ref.collection === target.ref.collection &&
      row.ref.locator === target.ref.locator &&
      (row.ref.kind ?? "") === (target.ref.kind ?? ""),
  );
}

/**
 * Publish the viewer target. `row` (the GridRow behind it) is optional: when
 * omitted, the current row context is kept if it still describes the target
 * (so a bridge that only forwards targets does not wipe the decoded fields).
 */
export function setViewerTarget(target: ViewerTarget | null, row?: GridRow | null): void {
  const nextRow = row !== undefined ? row : rowMatches(state.row, target) ? state.row : null;
  setState({ target, row: nextRow });
}

/** Publish the GridRow for the current (or the next) target — the grid calls this on focus. */
export function setViewerRowContext(row: GridRow | null): void {
  if (state.row !== row) setState({ row });
}

export function useViewerFocusRequest(): number {
  return useAdapter((s) => s.focusSeq);
}

export function requestViewerFocus(): void {
  setState({ focusSeq: state.focusSeq + 1 });
}

export function useViewerRouteMode(): {
  mode: ViewerMode | undefined;
  setMode: (mode: ViewerMode | undefined) => void;
} {
  const mode = useAdapter((s) => s.routeMode);
  return { mode, setMode: setViewerRouteMode };
}

export function getViewerRouteMode(): ViewerMode | undefined {
  return state.routeMode;
}

export function setViewerRouteMode(mode: ViewerMode | undefined): void {
  if (state.routeMode !== mode) setState({ routeMode: mode });
}

/** Row context for the current target only (a stale row for another target is ignored). */
export function useViewerRowContext(): GridRow | null {
  return useAdapter((s) => (rowMatches(s.row, s.target) ? s.row : null));
}

/** Route `q=` keywords (S1 store); falls back to parsing the hash when no case is routed. */
export function useHighlightTerms(): string[] {
  const routed = useAppStore((st) => (st.route.runId ? (st.route.q ?? "") : null));
  if (routed !== null) return parseHighlightTerms(routed ? `?q=${encodeURIComponent(routed)}` : "");
  const hash = typeof window === "undefined" ? "" : window.location.hash;
  return parseHighlightTerms(hash);
}

export function parseHighlightTerms(hash: string): string[] {
  const queryIndex = hash.indexOf("?");
  if (queryIndex < 0) return [];
  const q = new URLSearchParams(hash.slice(queryIndex + 1)).get("q") || "";
  return q
    .split(/[\s,]+/)
    .map((term) => term.trim())
    .filter((term) => term.length > 0);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

const shellOffs = new Map<string, () => void>();

/**
 * Register locally (toolbar lookups, tests) and in the S1 registry (palette,
 * key map, help). `viewer.mark.*` stay local: the shell's `review.mark.*`
 * commands (R/X/I/B) cover them with the same shared implementation.
 */
export function registerCommand(command: Command): () => void {
  commands.set(command.id, command);
  let offShell: (() => void) | null = null;
  if (!command.id.startsWith("viewer.mark.")) {
    try {
      offShell = registerShellCommand(command);
      shellOffs.set(command.id, offShell);
    } catch (error) {
      console.warn(error instanceof Error ? error.message : error);
    }
  }
  setState({ commandsVersion: state.commandsVersion + 1 });
  return () => {
    offShell?.();
    if (shellOffs.get(command.id) === offShell) shellOffs.delete(command.id);
    if (commands.get(command.id) === command) {
      commands.delete(command.id);
      setState({ commandsVersion: state.commandsVersion + 1 });
    }
  };
}

/** Local registration first, then the S1 registry (e.g. `navigate.rows-for-source`). */
export function getCommand(id: string): Command | undefined {
  return commands.get(id) ?? getShellCommand(id);
}

/** Re-renders when either registry changes (so "registered?" checks stay fresh). */
export function useCommandsVersion(): number {
  useShellCommands();
  return useAdapter((s) => s.commandsVersion);
}

/** S1 command context, with the viewer's own target as the fallback run/collection. */
export function useCommandContext(): CommandContext {
  const target = useViewerTarget();
  const shell = useShellCommandContext();
  return useMemo(
    () => ({
      ...shell,
      runId: shell.runId ?? target?.runId ?? null,
      collection: shell.collection ?? target?.ref.collection ?? null,
      viewerHasTarget: target !== null,
    }),
    [shell, target],
  );
}

/**
 * Re-render key for controls whose availability depends on the grid route (collection +
 * filter text), e.g. "같은 출처의 다른 행" — so their aria-disabled reason never goes stale.
 */
export function useRouteFilterKey(): string {
  return useAppStore((s) => `${s.route.collection ?? ""}|${s.route.q ?? ""}`);
}

export async function dispatchCommand(id: string, ctx: CommandContext): Promise<boolean> {
  const command = getCommand(id);
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("rapidtriage:command", { detail: { id, target: state.target } }));
  }
  if (!command) return false;
  if (command.disabledReason?.(ctx)) return false;
  await command.run(ctx);
  return true;
}

/** Test helper: reset the local adapter between tests. */
export function resetViewerAdapter(): void {
  resetViewerSession();
  for (const off of shellOffs.values()) off();
  shellOffs.clear();
  commands.clear();
  state = { target: null, focusSeq: 0, row: null, commandsVersion: 0, routeMode: undefined };
  for (const listener of listeners) listener();
}
