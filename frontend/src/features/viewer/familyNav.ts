/**
 * 계열 navigation (R7 갈래 A): the route that lists an item's family and shows one of its rows in
 * the 계열 tab. Shared by the viewer's 계열 tab and the grid row menu (계열 보기 · 상위 항목으로).
 *
 * Artifact rows open the artifacts list across kinds with `family=<top>` (a family can span kinds);
 * files rows the files list (inventory rows: `category=inventory`); analysis rows (carved) their
 * analysis list, which the server does not filter by family (the row is shown, the list is whole).
 */

import { parseItemRef, rowRefOfItem } from "../../api/families";
import type { RowRef } from "../../contracts/rowRef";
import type { Route } from "../../router";
import { useAppStore } from "../../state/store";
import { requestViewerMode } from "./session";

/** The analysis node kind of a carve analysis id (`…-carve…` ids; carving is the only family source). */
const CARVE_NODE = "carve";

/**
 * Route listing the family of `familyRef` (any member; the server lists the whole family) with
 * `rowRef`'s row in the viewer's 계열 tab; null when the row is no row (a source file).
 */
export function familyRoute(
  runId: string,
  rowItem: string,
  familyRef: string,
  mode: Route["mode"] = "family",
): Route | null {
  const parsed = parseItemRef(rowItem);
  const row: RowRef | null = rowRefOfItem(rowItem);
  if (!parsed || !row) return null;
  if (parsed.collection === "analysis") {
    return {
      runId,
      collection: "analysis",
      kind: CARVE_NODE,
      analysisId: parsed.kind,
      row,
      ...(mode ? { mode } : {}),
    };
  }
  const route: Route = {
    runId,
    collection: parsed.collection === "files" ? "files" : "artifacts",
    family: [familyRef],
    row,
    ...(mode ? { mode } : {}),
  };
  if (parsed.collection === "files" && row.locator.startsWith("/inventory/")) route.category = "inventory";
  return route;
}

/** Navigate to a family route; its row opens in the viewer's 계열 tab (not only on a page load). */
export function openFamilyRoute(route: Route): void {
  if (route.row && route.runId && route.mode) requestViewerMode(route.runId, route.row, route.mode);
  useAppStore.getState().navigate(route);
}
