/**
 * Adapter between the grid and the S1 shell (app/state/router/commands).
 *
 * The grid only imports hooks from THIS file. It currently ships a local
 * zustand-backed implementation so the grid and its tests run standalone; to
 * wire S1, re-implement these exports on top of `src/state/hooks.ts`:
 *
 *   useRoute()        -> { runId, collection: CollectionRef, q, search?, rowRef,
 *                          setQuery(q), setRow(ref|null), navigate(ref, q?) }
 *                        from S1 useRoute(): route.{runId,collection,kind,status,q,row};
 *                        setQuery = patchRoute({q}, {replace}), setRow = patchRoute({row}),
 *                        navigate = openCollection(id, {kind,status,q}).
 *   useSelection()    -> { selectedKeys: ReadonlySet<string>, focusedRowKey, select(keys), setFocused(key) }
 *                        from S1 useSelection(): selectedRowKeys / setSelectedRows / focusRow.
 *   useViewerTarget() -> { target, publish(t), requestFocus() }
 *                        from S1 useViewerTarget().setTarget; requestFocus = S1/S2 viewer-focus action.
 *   useDensity()      -> { density: "compact"|"default"|"comfortable", setDensity(d) } (same as S1).
 *   registerCommand(cmd) -> unregister()   (S1 commands/registry registerCommand; throws on duplicate ids)
 *   getRegisteredCommand(id) -> Command|undefined   (S1 getCommandsSnapshot().find)
 *   useToast()        -> { toasts, show(message, tone?), dismiss(id) }  (S1 toast slot, if any)
 */

import { create } from "zustand";
import { registerCommand as registerShellCommand } from "../../commands/registry";
import type { CollectionQuery, CollectionRef, GridRow, ServerSort } from "../../contracts/collection";
import type { Command } from "../../contracts/command";
import type { RowRef } from "../../contracts/rowRef";
import type { ViewerTarget } from "../../contracts/viewer";
import type { Density } from "./types";

export interface RouteState {
  runId: string | null;
  collection: CollectionRef;
  /** Grid filter text (`?q=` in the URL). */
  q: string;
  /** Search-collection spec (keywords etc.), owned by the route/search UI. */
  search?: CollectionQuery["search"];
  rowRef: RowRef | null;
  /** Server sort (artifacts of one kind; URL `sort=`). */
  sort?: ServerSort;
  /** Promoted record-field columns (artifacts of one kind; URL `cols=details.<key>,…`). */
  cols?: string[];
}

export interface Toast {
  id: number;
  message: string;
  tone: "error" | "info";
}

interface LocalState {
  route: RouteState;
  selectedKeys: ReadonlySet<string>;
  focusedRowKey: string | null;
  target: ViewerTarget | null;
  /** The focused GridRow (with reviewStatus/tags), published together with `target`. */
  focusedRow: GridRow | null;
  viewerFocusRequests: number;
  density: Density;
  toasts: Toast[];
  commands: Map<string, Command>;
  /** Column ids the mounted grid currently shows (preset + visibility); null when no grid is mounted. */
  visibleColumnIds: string[] | null;
  setVisibleColumnIds: (ids: string[] | null) => void;
  setRoute: (patch: Partial<RouteState>) => void;
  select: (keys: string[]) => void;
  setFocused: (key: string | null) => void;
  publish: (target: ViewerTarget | null) => void;
  publishFocusedRow: (row: GridRow | null, target: ViewerTarget | null) => void;
  requestViewerFocus: () => void;
  setDensity: (density: Density) => void;
  pushToast: (message: string, tone: Toast["tone"]) => void;
  dismissToast: (id: number) => void;
}

let toastSeq = 0;

export const useGridLocalStore = create<LocalState>((set) => ({
  route: { runId: null, collection: { id: "artifacts" }, q: "", rowRef: null },
  selectedKeys: new Set<string>(),
  focusedRowKey: null,
  target: null,
  focusedRow: null,
  viewerFocusRequests: 0,
  density: "default",
  toasts: [],
  commands: new Map(),
  visibleColumnIds: null,
  setVisibleColumnIds: (ids) => set({ visibleColumnIds: ids }),
  setRoute: (patch) => set((s) => ({ route: { ...s.route, ...patch } })),
  select: (keys) => set({ selectedKeys: new Set(keys) }),
  setFocused: (key) => set({ focusedRowKey: key }),
  publish: (target) => set({ target }),
  publishFocusedRow: (row, target) => set({ focusedRow: row, target, focusedRowKey: row?.rowKey ?? null }),
  requestViewerFocus: () => set((s) => ({ viewerFocusRequests: s.viewerFocusRequests + 1 })),
  setDensity: (density) => set({ density }),
  pushToast: (message, tone) => set((s) => ({ toasts: [...s.toasts, { id: ++toastSeq, message, tone }] })),
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));

/** Stable setters (usable in effect deps). */
function setRouteSort(sort: ServerSort | undefined): void {
  useGridLocalStore.getState().setRoute({ sort });
}

function setRouteCols(cols: string[] | undefined): void {
  useGridLocalStore.getState().setRoute({ cols: cols?.length ? cols : undefined });
}

export function useRoute() {
  const route = useGridLocalStore((s) => s.route);
  const setRoute = useGridLocalStore((s) => s.setRoute);
  return {
    ...route,
    setQuery: (q: string) => setRoute({ q }),
    setRow: (rowRef: RowRef | null) => setRoute({ rowRef }),
    setSort: setRouteSort,
    setCols: setRouteCols,
    navigate: (collection: CollectionRef, q = "") =>
      setRoute({ collection, q, rowRef: null, sort: undefined, cols: undefined }),
  };
}

export function useSelection() {
  const selectedKeys = useGridLocalStore((s) => s.selectedKeys);
  const focusedRowKey = useGridLocalStore((s) => s.focusedRowKey);
  const select = useGridLocalStore((s) => s.select);
  const setFocused = useGridLocalStore((s) => s.setFocused);
  return { selectedKeys, focusedRowKey, select, setFocused };
}

export function useViewerTarget() {
  const target = useGridLocalStore((s) => s.target);
  const publish = useGridLocalStore((s) => s.publish);
  const publishFocusedRow = useGridLocalStore((s) => s.publishFocusedRow);
  const focusedRow = useGridLocalStore((s) => s.focusedRow);
  const requestFocus = useGridLocalStore((s) => s.requestViewerFocus);
  return { target, publish, publishFocusedRow, focusedRow, requestFocus };
}

export function useDensity() {
  const density = useGridLocalStore((s) => s.density);
  const setDensity = useGridLocalStore((s) => s.setDensity);
  return { density, setDensity };
}

export function useToast() {
  const toasts = useGridLocalStore((s) => s.toasts);
  const pushToast = useGridLocalStore((s) => s.pushToast);
  const dismiss = useGridLocalStore((s) => s.dismissToast);
  return {
    toasts,
    show: (message: string, tone: Toast["tone"] = "error") => pushToast(message, tone),
    dismiss,
  };
}

/**
 * Register a command locally (RowMenu/BatchBar lookups, tests) AND in the S1
 * registry (palette, help, CommandButton). Returns the unregister function.
 */
export function registerCommand(command: Command): () => void {
  const store = useGridLocalStore;
  store.getState().commands.set(command.id, command);
  let offShell: (() => void) | null = null;
  try {
    offShell = registerShellCommand(command);
  } catch (error) {
    // A second mounted grid (or a leaked test render) already owns the id.
    console.warn(error instanceof Error ? error.message : error);
  }
  return () => {
    offShell?.();
    const map = store.getState().commands;
    if (map.get(command.id) === command) map.delete(command.id);
  };
}

/** Register a command for the grid's own menus only (not the palette/shortcut registry). */
export function registerLocalCommand(command: Command): () => void {
  const map = useGridLocalStore.getState().commands;
  map.set(command.id, command);
  return () => {
    const current = useGridLocalStore.getState().commands;
    if (current.get(command.id) === command) current.delete(command.id);
  };
}

export function getRegisteredCommand(id: string): Command | undefined {
  return useGridLocalStore.getState().commands.get(id);
}
