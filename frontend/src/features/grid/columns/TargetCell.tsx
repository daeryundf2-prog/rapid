import type { ReactNode } from "react";
import type { GridRow } from "../../../contracts/collection";
import { str } from "./common";
import { pathCell } from "./PathCell";

/**
 * 대상 cell (F10, review P1-1): the row's value is the whole target (URL with its query, full
 * path, full key) for copy / filter / CSV; only the cell shortens it — a path keeps its end
 * (MiddlePath), anything else shows the short display text.
 */
export function targetCell(row: GridRow): ReactNode {
  if (str(row.fields.targetKind) === "path") return pathCell(row.title);
  return str(row.fields.targetDisplay) || row.title;
}
