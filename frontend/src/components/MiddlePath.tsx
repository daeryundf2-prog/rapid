import { pathDisplayParts } from "../utils/pathDisplay";

/**
 * One path renderer for the grid 경로 column, the viewer header, the 보고 table and the action
 * dialogs (review #9, F28): mono, the end kept — the last segment (file name) whole, the two
 * folders before it next — and the middle elided ("/tmp/rd-da…alice/Documents/a.docx"). The
 * text is the whole path (screen readers and copy read it all); the full path is also the
 * tooltip and stays the cell's copy / filter value.
 */
export function MiddlePath({
  path,
  className,
  whole = false,
}: {
  path: string | null | undefined;
  className?: string;
  /** Show the whole path (grid cells, an evidence root), not its parent folder (viewer header). */
  whole?: boolean;
}) {
  const parts = pathDisplayParts(path, !whole);
  if (!parts || !path) return null;
  return (
    <span className={`mid-path${className ? ` ${className}` : ""}`} title={path}>
      {parts.head ? <span className="mid-path-head">{parts.head}</span> : null}
      <span className="mid-path-end">
        {parts.dirs ? (
          <span className="mid-path-dirs">
            {/* The folder box runs right-to-left so it overflows (and ellipsizes) at its start; the
                path itself keeps its left-to-right order. */}
            <bdo dir="ltr">{parts.dirs}</bdo>
          </span>
        ) : null}
        <span className="mid-path-tail">{parts.tail}</span>
      </span>
    </span>
  );
}
