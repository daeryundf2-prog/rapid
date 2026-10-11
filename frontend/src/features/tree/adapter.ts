/**
 * Local adapter between the S4 feature code (tree, case dialogs, commands) and
 * the shell owned by S1.
 *
 * Integrated with S1: the bodies below delegate to the shell (router store,
 * command registry, runs poller). Every S4 import keeps pointing at THIS file:
 *
 *  - `useRoute()`            -> S1 router hook: the current `CaseRoute | null`
 *                               parsed from `#/case/{run}/{collection}[/{kind|status}]`.
 *  - `navigate(route)`       -> S1 router: push a route (hash) entry.
 *  - `registerCommand(cmd)`  -> S1 command registry: returns an unregister fn.
 *  - `useRunLive(runId)`     -> S1 runs poller (one shared react-query entry).
 */

import { useMemo } from "react";
import { useShallow } from "zustand/react/shallow";
import { useRunsPoll } from "../../api/runsProgress";
import { focusGridWhenReady } from "../../commands/builtin";
import { getCommands, registerCommand as registerShellCommand, useCommands } from "../../commands/registry";
import type { CollectionId, ReviewStatus } from "../../contracts/collection";
import type { Command } from "../../contracts/command";
import { isRunActive } from "../../state/slices/runs";
import { useAppStore } from "../../state/store";

export interface CaseRoute {
  runId: string;
  collection: CollectionId;
  /** Artifact kind (collection === "artifacts") or review status (collection === "review"). */
  kind?: string;
  status?: ReviewStatus;
  /** Artifact category node (collection === "artifacts", no kind): `?category=<id>`. */
  category?: string;
}

const COLLECTIONS: readonly CollectionId[] = [
  "intake",
  "search",
  "files",
  "docs",
  "artifacts",
  "timeline",
  "indicators",
  "review",
  "outputs",
];

/** `#/case/{run}/{collection}[/{kind}][?category=…]` (other `?q=…&row=…` keys are ignored here). */
export function parseRoute(hash: string): CaseRoute | null {
  const [path = "", query = ""] = hash.replace(/^#/, "").split("?");
  const parts = path.split("/").filter(Boolean);
  if (parts[0] !== "case" || !parts[1]) return null;
  const collection = (parts[2] ?? "intake") as CollectionId;
  if (!COLLECTIONS.includes(collection)) return null;
  const rest = parts[3] ? decodeURIComponent(parts[3]) : undefined;
  const route: CaseRoute = { runId: decodeURIComponent(parts[1]), collection };
  if (collection === "review" && rest) route.status = rest as ReviewStatus;
  else if (rest) route.kind = rest;
  const category = new URLSearchParams(query).get("category");
  if (collection === "artifacts" && !route.kind && category) route.category = category;
  return route;
}

export function formatRoute(route: CaseRoute): string {
  const tail = route.status ?? route.kind;
  const base = `#/case/${encodeURIComponent(route.runId)}/${route.collection}${tail ? `/${encodeURIComponent(tail)}` : ""}`;
  return route.category && !tail ? `${base}?category=${encodeURIComponent(route.category)}` : base;
}

export function sameRoute(a: CaseRoute | null, b: CaseRoute): boolean {
  return (
    a !== null &&
    a.runId === b.runId &&
    a.collection === b.collection &&
    (a.kind ?? null) === (b.kind ?? null) &&
    (a.status ?? null) === (b.status ?? null) &&
    (a.category ?? null) === (b.category ?? null)
  );
}

/** Current case route from the S1 store (hash is the source of truth). */
export function useRoute(): CaseRoute | null {
  const { runId, collection, kind, status, category } = useAppStore(
    useShallow((st) => ({
      runId: st.route.runId,
      collection: st.route.collection,
      kind: st.route.kind,
      status: st.route.status,
      category: st.route.category,
    })),
  );
  return useMemo(() => {
    if (!runId || !collection) return null;
    const route: CaseRoute = { runId, collection };
    if (kind) route.kind = kind;
    if (status) route.status = status;
    if (category) route.category = category;
    return route;
  }, [runId, collection, kind, status, category]);
}

/** Push a route through the S1 router (keeps the viewer row within the same run, plan U1). */
export function navigate(route: CaseRoute): void {
  useAppStore.getState().openCollection(route.collection, {
    runId: route.runId,
    kind: route.kind,
    status: route.status,
    category: route.category,
  });
  // Tree / palette navigation lands in the grid: J and Enter work without a click.
  focusGridWhenReady();
}

// ---- command registry (S1 palette registry) --------------------------------

/** S1 command registry (palette, key map, help). */
export function registerCommand(command: Command): () => void {
  return registerShellCommand(command);
}

export function getRegisteredCommands(): Command[] {
  return getCommands();
}

export function useRegisteredCommands(): Command[] {
  return useCommands();
}

// ---- live run progress ------------------------------------------------------

export interface RunLive {
  /** true while any run is queued/running. */
  anyActive: boolean;
  /** this run is queued/running. */
  active: boolean;
  completed: number | null;
  total: number | null;
  errors: number;
}

/** Backed by the shell's single runs poller (api/runsProgress.ts, shared react-query entry). */
export function useRunLive(runId: string | null): RunLive {
  const rows = useRunsPoll().data ?? [];
  const mine = runId ? rows.find((r) => r.run_id === runId) : undefined;
  return {
    anyActive: rows.some(isRunActive),
    active: isRunActive(mine),
    completed: mine?.progress?.completed_count ?? null,
    total: mine?.progress?.total_count ?? null,
    errors: mine?.progress?.error_count ?? 0,
  };
}
