import type { ReactNode } from "react";
import { splitPathTail } from "../gridUtils";

/**
 * 경로 cell (visual-polish B2 #2): truncates in the middle — the folder part ellipsizes, the file
 * name stays whole. The text content is the full path (copy / filter / tooltip unchanged).
 */
export function pathCell(path: string | null): ReactNode {
  if (!path) return null;
  const [head, tail] = splitPathTail(path);
  if (!head) return path;
  return (
    <span className="grid-path">
      <span className="grid-path-head">{head}</span>
      <span className="grid-path-tail">{tail}</span>
    </span>
  );
}
