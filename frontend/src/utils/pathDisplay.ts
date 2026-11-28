/**
 * Path display (review #9 / F28): grid 경로 cells, the viewer header, the 보고 table and the
 * action dialogs keep the END of a path — the last two folders and the last segment (the file
 * name with its extension) — and elide the middle: the leading part ("C:\Users\…") gives way
 * first, then the two folders from their start, the last segment last. No gap is inserted
 * between the parts: what is on screen reads as the path itself.
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

export interface PathEndParts {
  /** Leading part, elided first ("/tmp/rd-data/evidence/Users/"); "" for a short path. */
  head: string;
  /** Up to two folders before the last segment, separators kept ("alice/Documents/"). */
  dirs: string;
  /** Last segment (the file name), never elided before the others. */
  tail: string;
}

/** How many folders before the last segment stay with it. */
const KEPT_DIRS = 2;

/**
 * "/tmp/e/Users/alice/Documents/a.docx" → { head: "/tmp/e/Users/", dirs: "alice/Documents/",
 * tail: "a.docx" }. A root ("/", "C:\") or a bare name is all tail; a trailing separator is
 * dropped. Concatenated, the parts are the path as written.
 */
export function pathEndParts(path: string): PathEndParts {
  if (/^([A-Za-z]:)?[\\/]$/.test(path)) return { head: "", dirs: "", tail: path };
  const trimmed = path.replace(/[\\/]+$/, "") || path;
  // Separator positions; each part keeps the separator that ends it.
  const cuts: number[] = [];
  for (let i = 0; i < trimmed.length; i++) if (trimmed[i] === "/" || trimmed[i] === "\\") cuts.push(i);
  const last = cuts.at(-1);
  if (last === undefined || last === trimmed.length - 1) return { head: "", dirs: "", tail: trimmed };
  const tail = trimmed.slice(last + 1);
  // The folders kept with the tail start after the separator KEPT_DIRS + 1 from the end; a
  // leading "/" (or "C:\") is the head's, so "/a/b/c" keeps "a/b/" with the tail.
  const from = cuts.length > KEPT_DIRS ? (cuts[cuts.length - 1 - KEPT_DIRS] as number) + 1 : 0;
  const head = trimmed.slice(0, from);
  const dirs = trimmed.slice(from, last + 1);
  if (from === 0 && /^([A-Za-z]:)?[\\/]/.test(dirs)) {
    const root = /^([A-Za-z]:)?[\\/]/.exec(dirs)?.[0] ?? "";
    return { head: root, dirs: dirs.slice(root.length), tail };
  }
  return { head, dirs, tail };
}

/**
 * What a path renderer shows: the whole path, or (`parentOnly`, the viewer header whose title is
 * the file name) its parent folder; a bare name shows itself; null / "" shows nothing.
 */
export function pathDisplayParts(path: string | null | undefined, parentOnly = false): PathEndParts | null {
  if (!path) return null;
  const shown = parentOnly ? parentDir(path) || path : path;
  return pathEndParts(shown);
}
