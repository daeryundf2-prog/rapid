import type { ReactNode } from "react";
import type { GridRow } from "../../../contracts/collection";

/** Separator of `fields.timeKinds` (the Korean time kinds of one event, primary first). */
export const TIME_KINDS_SEPARATOR = " · ";

/**
 * 시각 종류 cell (parser-quality r2 `labels[]`): the primary kind, then a compact "+n" chip when
 * other time kinds of the same record and instant were merged into the event. The chip's title
 * and the screen-reader text list every kind.
 */
export function timeKindsCell(row: GridRow): ReactNode {
  const text = typeof row.fields.timeKinds === "string" ? row.fields.timeKinds : "";
  const labels = text ? text.split(TIME_KINDS_SEPARATOR).filter(Boolean) : [];
  const [primary, ...rest] = labels;
  if (!primary) {
    return (
      <span className="grid-cell-empty" aria-hidden="true">
        —
      </span>
    );
  }
  if (!rest.length) return <span className="grid-cell-text">{primary}</span>;
  return (
    <span className="grid-chips" data-testid="timeline-time-kinds">
      <span className="grid-cell-text">{primary}</span>
      <span className="grid-tag-chip" title={labels.join(TIME_KINDS_SEPARATOR)} aria-hidden="true">
        +{rest.length}
      </span>
      <span className="sr-only">(같은 시각: {rest.join(", ")})</span>
    </span>
  );
}
