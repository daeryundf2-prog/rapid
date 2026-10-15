import type { ReactNode } from "react";
import { StatusChip } from "../../../components/StatusChip";
import type { GridRow } from "../../../contracts/collection";
import { artifactTypeLabel } from "../../filters/typeLabels";

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

/** `--tag-1` … `--tag-7` colour real types; `--tag-8` (the muted one) is reserved for "other". */
const TYPE_COLOURS = 7;
export const OTHER_TYPE_COLOUR = 8;
/** Catch-all type names that get the reserved "other" colour (review #9). */
const OTHER_TYPES = new Set(["other", "others", "unknown", "misc", "generic", "기타", "알 수 없음"]);

/**
 * Deterministic colour slot of an artifact type: the same type always gets the same dot, real
 * types spread over tag-1…7, and catch-all types ("other", "unknown", 기타) take tag-8.
 */
export function typeColourIndex(type: string): number {
  if (OTHER_TYPES.has(type.trim().toLowerCase())) return OTHER_TYPE_COLOUR;
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
      {/* Korean type name (review: evidence-first viewer §7); the id stays the tooltip. */}
      <span className="grid-type-text" data-type={row.artifactType}>
        {artifactTypeLabel(row.artifactType) ?? row.artifactType}
      </span>
    </span>
  );
}
