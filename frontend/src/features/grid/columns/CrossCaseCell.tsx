import type { ReactNode } from "react";
import type { GridRow } from "../../../contracts/collection";
import { useAppStore } from "../../../state/store";
import { caseHref, caseLabel, crossCaseRunIds } from "../../analysis/crossCase";
import { isRecord } from "./common";

/**
 * 케이스 cell of a cross-case result row: one link per case that opens that run (at the
 * occurrence's row / path when known). Links stay out of the grid's tab order (one tab stop
 * per grid); keyboard users reach the same targets from the row menu and the viewer 메타 tab.
 */
export function crossCaseCasesCell(row: GridRow): ReactNode {
  const details = isRecord(row.fields.details) ? row.fields.details : {};
  const current = useAppStore.getState().route.runId;
  const ids = crossCaseRunIds(details);
  if (ids.length === 0) return null;
  return (
    <span className="grid-case-links">
      {ids.map((id, index) => (
        <span key={id}>
          {index > 0 ? ", " : null}
          {id === current ? (
            <span title="현재 케이스">{caseLabel(id)} (현재)</span>
          ) : (
            <a className="grid-case-link" href={caseHref(details, id)} tabIndex={-1} data-case-run={id}>
              {caseLabel(id)}
            </a>
          )}
        </span>
      ))}
    </span>
  );
}
