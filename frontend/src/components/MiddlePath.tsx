import { pathCellParts } from "../utils/pathDisplay";

/**
 * One path renderer for the grid 경로 column, the viewer header, the 보고서 table and the landing
 * (review #9, plan r7 §3.2 L2 C-D8 / C-W6 / C-L3; r8 C.9.1): the whole path, mono, TAIL FIRST
 * with ONE front ellipsis — the text is laid out right-to-left inside an isolated left-to-right
 * run, so a narrow cell cuts the head under a single leading "…" and the file name stays (never
 * a second ellipsis in the middle). The parts keep their own colours. The tooltip is `title`
 * (default the path); the text always holds the name.
 */
export function MiddlePath({
  path,
  className,
  whole = false,
  title,
}: {
  path: string | null | undefined;
  className?: string;
  /** An evidence root (a folder, not a file): same tail-first layout, marked for its styles. */
  whole?: boolean;
  /** Tooltip; defaults to the path itself. */
  title?: string;
}) {
  const parts = pathCellParts(path);
  if (!parts || !path) return null;
  return (
    <span
      className={`mid-path mid-path-front${whole ? " mid-path-whole" : ""}${className ? ` ${className}` : ""}`}
      title={title ?? path}
    >
      <bdi className="mid-path-text" dir="ltr">
        {parts.head ? <span className="mid-path-head">{parts.head}</span> : null}
        {parts.parents ? <span className="mid-path-parents">{parts.parents}</span> : null}
        <span className="mid-path-tail">{parts.name}</span>
      </bdi>
    </span>
  );
}
