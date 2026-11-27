import { middlePathParts, pathCellParts } from "../utils/pathDisplay";

/**
 * One path renderer for the grid 경로 column, the viewer header, the 보고 table and the action
 * dialogs (review #9): the parent folder (or the whole path), mono, the last segment kept whole
 * and the leading folders cut from the front ("…\User Data\Default\History"), so the folders
 * nearest the file stay readable. The full path is the tooltip (and stays the cell's copy /
 * filter value).
 */
export function MiddlePath({
  path,
  className,
  whole = false,
}: {
  path: string | null | undefined;
  className?: string;
  /** Show the whole path (an evidence root, a timeline event's file), not its parent folder. */
  whole?: boolean;
}) {
  const parts = whole ? (path ? middlePathParts(path) : null) : pathCellParts(path);
  if (!parts || !path) return null;
  return (
    <span className={`mid-path${className ? ` ${className}` : ""}`} title={path}>
      {parts.head ? (
        <span className="mid-path-head">
          {/* The head box runs right-to-left so it overflows (and ellipsizes) at its start; the
              path itself keeps its left-to-right order. */}
          <bdo dir="ltr">{parts.head}</bdo>
        </span>
      ) : null}
      <span className="mid-path-tail">{parts.tail}</span>
    </span>
  );
}
