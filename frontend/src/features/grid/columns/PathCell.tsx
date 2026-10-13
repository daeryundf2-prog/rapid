import type { ReactNode } from "react";
import { MiddlePath } from "../../../components/MiddlePath";

/**
 * 경로 cell (review #9): the parent folder with the shared middle ellipsis (the 항목 column
 * already names the file). The cell's value / tooltip / filter text stay the full path.
 */
export function pathCell(path: string | null): ReactNode {
  if (!path) return null;
  return <MiddlePath path={path} />;
}
