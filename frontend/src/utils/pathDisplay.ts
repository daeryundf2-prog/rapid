/**
 * Path display (review #9 / #6, plan r7 §3.2 L2 C-D8): grid 경로 cells, the viewer header, the
 * 보고 table and the landing show the path TAIL FIRST — the file name and its two parent folders
 * stay, the leading folders ellipsize ("…"); the full path is the tooltip.
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

export interface TailPathParts {
  /** Leading folders (ellipsize first); "" when the path has no more than the kept tail. */
  head: string;
  /** The kept parent folders with their separators ("Users\\kim\\"); ellipsize second. */
  parents: string;
  /** The last segment (the file name): never truncated before the others. */
  name: string;
}

/**
 * Tail-first path parts (C-D8, plan r7 §3.2 L2): the file name plus its `keep` parent folders
 * stay readable, only the head gives way. "C:\a\b\c\d.txt" → head "C:\a\", parents
 * "b\c\", name "d.txt". A trailing separator is dropped; a root is its own name.
 */
export function tailPathParts(path: string, keep = 2): TailPathParts {
  if (/^([A-Za-z]:)?[\\/]$/.test(path)) return { head: "", parents: "", name: path };
  const trimmed = path.replace(/[\\/]+$/, "") || path;
  // Split keeping each separator on the segment before it.
  const segments = trimmed.match(/[^\\/]*[\\/]|[^\\/]+$/g) ?? [trimmed];
  const name = segments.pop() ?? "";
  const parents = segments.slice(Math.max(0, segments.length - keep));
  const head = segments.slice(0, Math.max(0, segments.length - keep));
  return { head: head.join(""), parents: parents.join(""), name };
}

/**
 * What a path cell shows: the whole path, tail first (file name + two parent folders; the head
 * ellipsizes). null / "" shows nothing.
 */
export function pathCellParts(path: string | null | undefined): TailPathParts | null {
  if (!path) return null;
  return tailPathParts(path);
}
