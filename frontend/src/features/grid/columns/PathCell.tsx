import type { ReactNode } from "react";
import { MiddlePath } from "../../../components/MiddlePath";

/**
 * 경로 cell (review #9): the parent folder with the shared middle ellipsis (the 항목 column
 * already names the file); `whole` shows the whole path, file name last and kept, for a listing
 * whose title is not the file name (타임라인: 요약). The cell's value / tooltip / filter text stay
 * the full path.
 */
export function pathCell(path: string | null, whole = false): ReactNode {
  if (!path) return null;
  return <MiddlePath path={path} whole={whole} />;
}
