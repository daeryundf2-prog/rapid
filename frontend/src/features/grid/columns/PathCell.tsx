import type { ReactNode } from "react";
import { MiddlePath } from "../../../components/MiddlePath";

/**
 * 경로 cell (F28): the whole path with its end kept — the last two folders and the file name with
 * its extension — and the middle elided, so a cell names the file and where it sits even when
 * narrow. The cell's value / tooltip / filter text stay the full path.
 */
export function pathCell(path: string | null): ReactNode {
  if (!path) return null;
  return <MiddlePath path={path} whole />;
}
