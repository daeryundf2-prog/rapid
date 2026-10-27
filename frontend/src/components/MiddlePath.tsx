import { pathCellParts } from "../utils/pathDisplay";

/**
 * One path renderer for the grid 경로 column, the viewer header, the 보고 table and the landing
 * (review #9, plan r7 §3.2 L2 C-D8 / C-W6 / C-L3): the whole path, mono, TAIL FIRST — the file
 * name never shrinks, its two parent folders shrink next, the head ellipsizes first. The full
 * path is the tooltip (and stays the cell's copy / filter value); the text always holds the name.
 */
export function MiddlePath({
  path,
  className,
  whole = false,
}: {
  path: string | null | undefined;
  className?: string;
  /** An evidence root (a folder, not a file): same tail-first layout, marked for its styles. */
  whole?: boolean;
}) {
  const parts = pathCellParts(path);
  if (!parts || !path) return null;
  return (
    <span
      className={`mid-path${whole ? " mid-path-whole" : ""}${className ? ` ${className}` : ""}`}
      title={path}
    >
      {parts.head ? <span className="mid-path-head">{parts.head}</span> : null}
      {parts.parents ? <span className="mid-path-parents">{parts.parents}</span> : null}
      <span className="mid-path-tail">{parts.name}</span>
    </span>
  );
}
