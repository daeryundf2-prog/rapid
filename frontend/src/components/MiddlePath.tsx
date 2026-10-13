import { middlePathParts, pathCellParts } from "../utils/pathDisplay";

/**
 * One path renderer for the grid 경로 column, the viewer header and the 보고 table (review #9):
 * the parent folder, mono, the head ellipsized in the middle and the last folder kept whole.
 * The full path is the tooltip (and stays the cell's copy / filter value).
 */
export function MiddlePath({
  path,
  className,
  whole = false,
}: {
  path: string | null | undefined;
  className?: string;
  /** Show the whole path (an evidence root), not its parent folder. */
  whole?: boolean;
}) {
  const parts = whole ? (path ? middlePathParts(path) : null) : pathCellParts(path);
  if (!parts || !path) return null;
  return (
    <span className={`mid-path${className ? ` ${className}` : ""}`} title={path}>
      {parts.head ? <span className="mid-path-head">{parts.head}</span> : null}
      <span className="mid-path-tail">{parts.tail}</span>
    </span>
  );
}
