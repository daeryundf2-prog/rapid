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

/** Number of `--tag-N` colour tokens (tokens.css). */
const TYPE_COLOURS = 8;

/** Deterministic colour slot (1..8) of an artifact type: the same type always gets the same dot. */
export function typeColourIndex(type: string): number {
  let hash = 0;
  for (let i = 0; i < type.length; i += 1) hash = (hash * 31 + type.charCodeAt(i)) >>> 0;
  return (hash % TYPE_COLOURS) + 1;
}

/** 유형 column (visual-polish S4): a colour dot + the type text, not a pill chip. */
export function typeChipCell(row: GridRow): ReactNode {
  if (!row.artifactType) return null;
  return (
    <span className="grid-type">
      <span
        className="grid-type-dot"
        aria-hidden="true"
        data-type-colour={typeColourIndex(row.artifactType)}
        style={{ background: `var(--tag-${typeColourIndex(row.artifactType)})` }}
      />
      <span className="grid-type-text">{row.artifactType}</span>
    </span>
  );
}
