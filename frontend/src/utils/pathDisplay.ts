/**
 * Path display (review #9 / #6, plan r7 §3.2 L2 C-D8): grid 경로 cells, the viewer header, the
 * 보고 table and the landing show the path TAIL FIRST — the file name and its two parent folders
 * stay, the front gives way under ONE leading ellipsis ("…", r8 C.9.1); the full path is the
 * tooltip. Listed paths are paths inside the evidence (`evidencePathOf`), not the result folder.
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

/**
 * Stage folders a run extracts an image's file system into (core/run: `_e01` · `_disk_image` ·
 * `_archive_image` · `_virtual_disk`, each holding `fs` or the legacy `filesystem`). Everything up
 * to and including that pair is the analysis PC's result folder, not a path inside the evidence.
 */
const RESULT_STAGE = /[\\/]_(?:e01|disk_image|archive_image|virtual_disk)[\\/](?:fs|filesystem)(?=[\\/]|$)/i;

/**
 * Pseudo folders the tools put recovered items in (`_deleted_mft`: the native E01 engine's
 * deleted-record sweep; `$OrphanFiles`: The Sleuth Kit's orphan folder). An item under one has
 * no known original location (r8 C.9.1, IS-128).
 */
const RECOVERY_FOLDERS: ReadonlySet<string> = new Set(["_deleted_mft", "$orphanfiles"]);

export interface EvidencePath {
  /**
   * The path inside the evidence ("\\Users\\kim\\a.txt"; "C:\\Users\\kim\\a.txt" when the volume
   * letter is known; the path itself when it holds no result folder). null when the original
   * location is unknown (recovery pseudo folder) or there is no path.
   */
  path: string | null;
  /** True when a result-folder prefix was removed. */
  stripped: boolean;
  /** True when the item sits in a recovery pseudo folder: its original location is unknown. */
  locationUnknown: boolean;
}

/** "c" / "C:" / "c:\\" → "C:"; anything else → "". */
function volumeLetter(volume: string | null | undefined): string {
  const match = /^\s*([A-Za-z]):?[\\/]?\s*$/.exec(volume ?? "");
  return match?.[1] ? `${match[1].toUpperCase()}:` : "";
}

/**
 * The in-evidence path of a listed path (r8 C.9.1, IS-128 / GAP-335): the result-folder prefix
 * (`…\_e01\fs\`) is removed and the rest is rooted at the volume — "C:\\…" when `volume` names
 * the letter, else the volume root "\\…". A path with no result folder (a folder input's own
 * files) is already an evidence path and is returned as it is.
 */
export function evidencePathOf(path: string | null | undefined, volume?: string | null): EvidencePath {
  if (!path) return { path: null, stripped: false, locationUnknown: false };
  const match = RESULT_STAGE.exec(path);
  if (!match) {
    const unknown = path.split(/[\\/]/).some((segment) => RECOVERY_FOLDERS.has(segment.toLowerCase()));
    return { path: unknown ? null : path, stripped: false, locationUnknown: unknown };
  }
  const sep = path.includes("\\") ? "\\" : "/";
  const segments = path
    .slice(match.index + match[0].length)
    .split(/[\\/]/)
    .filter(Boolean);
  if (RECOVERY_FOLDERS.has((segments[0] ?? "").toLowerCase())) {
    return { path: null, stripped: true, locationUnknown: true };
  }
  return {
    path: `${volumeLetter(volume)}${sep}${segments.join(sep)}`,
    stripped: true,
    locationUnknown: false,
  };
}

/**
 * A record value as the screen shows it (IS-128): every string holding a result-folder path
 * (`…\_e01\fs\…`), at any depth, reads as its in-evidence path, or `unknown` when it sits in a
 * recovery pseudo folder. Other values are returned as they are (the same object when untouched).
 */
export function evidenceDisplayValue(value: unknown, unknown: string): unknown {
  if (typeof value === "string") {
    if (!RESULT_STAGE.test(value)) return value;
    return evidencePathOf(value).path ?? unknown;
  }
  if (Array.isArray(value)) {
    const mapped = value.map((item) => evidenceDisplayValue(item, unknown));
    return mapped.some((item, index) => item !== value[index]) ? mapped : value;
  }
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const entries = Object.entries(value as Record<string, unknown>);
    const mapped = entries.map(([key, item]) => [key, evidenceDisplayValue(item, unknown)] as const);
    return mapped.some(([, item], index) => item !== entries[index]?.[1])
      ? Object.fromEntries(mapped)
      : value;
  }
  return value;
}

/**
 * The folder a files 경로 cell shows (the 이름 column already names the file): the in-evidence
 * parent folder; a file at the volume root shows the root. null when the location is unknown.
 */
export function evidenceFolderOf(path: string | null | undefined, volume?: string | null): string | null {
  const evidence = evidencePathOf(path, volume).path;
  if (!evidence) return null;
  return parentDir(evidence) || evidence;
}
