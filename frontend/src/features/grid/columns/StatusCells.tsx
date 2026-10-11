import type { ReactNode } from "react";
import { StatusChip } from "../../../components/StatusChip";
import type { GridRow } from "../../../contracts/collection";

/** Tags that map onto a fixed status colour (X3); every other tag renders as a neutral chip. */
const TAG_STATUS: Record<string, "bookmark"> = { 북마크: "bookmark", bookmark: "bookmark" };

/** 선별 column: the review status as a coloured chip (empty when unmarked). */
export function reviewStatusCell(row: GridRow): ReactNode {
  return row.reviewStatus ? <StatusChip status={row.reviewStatus} /> : null;
}

/** AXIOM 태그·상태 column: status chip followed by tag chips. */
export function tagStatusCell(row: GridRow): ReactNode {
  if (!row.reviewStatus && row.tags.length === 0) return null;
  return (
    <span className="grid-chips">
      {row.reviewStatus ? <StatusChip status={row.reviewStatus} /> : null}
      {row.tags.map((tag) => {
        const status = TAG_STATUS[tag];
        return status ? (
          <StatusChip key={tag} status={status} label={tag} />
        ) : (
          <span key={tag} className="grid-tag-chip">
            #{tag}
          </span>
        );
      })}
    </span>
  );
}
