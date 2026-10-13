/**
 * Path display (review #9 / #6): grid 경로 cells, the viewer header and the 보고 table show the
 * PARENT folder (the file name is already the row's title) with one consistent middle ellipsis —
 * the leading part ellipsizes ("…"), the last folder stays whole, 4px apart.
 */

/** "C:\a\b\file.txt" → "C:\a\b"; "/var/log/syslog" → "/var/log"; "file.txt" → "" (no parent). */
export function parentDir(path: string): string {
  const trimmed = path.replace(/[\\/]+$/, "");
  const cut = Math.max(trimmed.lastIndexOf("\\"), trimmed.lastIndexOf("/"));
  if (cut < 0) return "";
  // Keep a root's separator ("/x" → "/", "C:\x" → "C:\").
  if (cut === 0) return trimmed.slice(0, 1);
  if (cut === 2 && trimmed[1] === ":") return trimmed.slice(0, 3);
  return trimmed.slice(0, cut);
}

export interface MiddlePathParts {
  /** Leading part (ellipsizes when the cell is too narrow); "" when the path is one segment. */
  head: string;
  /** Last segment, never truncated before the head. */
  tail: string;
}

/** "C:\a\b\c" → { head: "C:\a\b\", tail: "c" }; "c" → { head: "", tail: "c" }. */
export function middlePathParts(path: string): MiddlePathParts {
  // A root ("/", "C:\") is one segment of its own.
  if (/^([A-Za-z]:)?[\\/]$/.test(path)) return { head: "", tail: path };
  const trimmed = path.replace(/[\\/]+$/, "") || path;
  const cut = Math.max(trimmed.lastIndexOf("\\"), trimmed.lastIndexOf("/"));
  if (cut < 0 || cut === trimmed.length - 1) return { head: "", tail: trimmed };
  return { head: trimmed.slice(0, cut + 1), tail: trimmed.slice(cut + 1) };
}

/**
 * What a path cell shows: the parent folder split for the middle ellipsis. A bare file name
 * (no parent) shows itself; null / "" shows nothing.
 */
export function pathCellParts(path: string | null | undefined): MiddlePathParts | null {
  if (!path) return null;
  const dir = parentDir(path);
  return middlePathParts(dir || path);
}
