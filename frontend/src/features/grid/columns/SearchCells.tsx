import type { ReactNode } from "react";
import type { GridRow } from "../../../contracts/collection";
import type { MatchContext } from "./searchMatch";

/**
 * 일치 문맥 cell (F11): plain text around the hit, the hit itself in `<mark>`; a hit without a
 * readable context shows the row's fallback text (`fields.preview`), never a JSON dump. A narrow
 * cell trims the text before the hit from its start, so the hit stays on screen.
 */
export function matchContextCell(row: GridRow): ReactNode {
  const context = row.fields.matchContext as MatchContext | null | undefined;
  if (!context) {
    const text = typeof row.fields.preview === "string" ? row.fields.preview : "";
    return text ? <span className="grid-cell-text">{text}</span> : null;
  }
  return (
    <span className="grid-cell-text search-context">
      <span className="search-before">
        <bdo dir="ltr">
          {context.cutStart ? "…" : ""}
          {/* A space right before the hit would collapse at the end of the RTL box. */}
          {context.before.replace(/ $/, "\u00a0")}
        </bdo>
      </span>
      <mark className="search-hit">{context.hit}</mark>
      <span className="search-after">
        {context.after}
        {context.cutEnd ? "…" : ""}
      </span>
    </span>
  );
}
