import type { ReactNode } from "react";
import type { GridRow } from "../../../contracts/collection";

/** Separator of `fields.timeKinds` (the Korean time kinds of one event, primary first). */
export const TIME_KINDS_SEPARATOR = " · ";

/**
 * 출처 N cell (timeline display groups, `group=1`): a chip with the number of sources that recorded
 * the same target at the same second with the same kind of time; nothing for a single source.
 */
export function sourceCountCell(row: GridRow): ReactNode {
  const count = typeof row.fields.sourceCount === "number" ? row.fields.sourceCount : 1;
  if (count <= 1) {
    return (
      <span className="grid-cell-empty" aria-hidden="true">
        —
      </span>
    );
  }
  return (
    <span className="grid-tag-chip" data-testid="timeline-source-count">
      출처 {count}
    </span>
  );
}

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
