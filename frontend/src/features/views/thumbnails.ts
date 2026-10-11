/**
 * Thumbnail model (S9, plan X16). Pure: which rows are images, sort orders
 * and ARIA-grid keyboard movement over a row-major tile grid.
 */

import type { GridRow } from "../../contracts/collection";

export const IMAGE_EXTENSIONS: ReadonlySet<string> = new Set([
  "jpg",
  "jpeg",
  "jpe",
  "jfif",
  "png",
  "gif",
  "bmp",
  "dib",
  "webp",
  "tif",
  "tiff",
  "heic",
  "heif",
  "ico",
]);

export function rowExtension(row: GridRow): string {
  const field = row.fields.extension;
  if (typeof field === "string" && field) return field.replace(/^\.+/, "").toLowerCase();
  const match = /\.([A-Za-z0-9]{1,8})$/.exec(row.sourcePath ?? "");
  return match?.[1] ? match[1].toLowerCase() : "";
}

/** A row with a source path whose extension is a still-image format. */
export function isImageRow(row: GridRow): boolean {
  if (!row.sourcePath) return false;
  const type = (row.artifactType ?? "").toLowerCase();
  if (type === "media-video" || type === "media-audio") return false;
  if (type === "media-image") return true;
  return IMAGE_EXTENSIONS.has(rowExtension(row));
}

export function rowSize(row: GridRow): number | null {
  const direct = row.fields.size;
  if (typeof direct === "number") return direct;
  const details = row.fields.details as Record<string, unknown> | undefined;
  for (const key of ["size", "size_bytes", "file_size"]) {
    const value = details?.[key];
    if (typeof value === "number") return value;
  }
  return null;
}

function rowName(row: GridRow): string {
  const path = row.sourcePath ?? "";
  return (path.split(/[\\/]/).pop() || row.title).toLowerCase();
}

export type ThumbSort = "name-asc" | "name-desc" | "date-desc" | "date-asc" | "size-desc" | "size-asc";

export const THUMB_SORT_LABELS: Record<ThumbSort, string> = {
  "name-asc": "이름 (가나다순)",
  "name-desc": "이름 (역순)",
  "date-desc": "날짜 (최신순)",
  "date-asc": "날짜 (오래된순)",
  "size-desc": "크기 (큰 순)",
  "size-asc": "크기 (작은 순)",
};

function timeOf(row: GridRow): number | null {
  if (!row.timestamp) return null;
  const ms = Date.parse(row.timestamp);
  return Number.isNaN(ms) ? null : ms;
}

/** Stable sort; rows without the sort value go last in either direction. */
export function sortThumbs(rows: readonly GridRow[], sort: ThumbSort): GridRow[] {
  const [field, dir] = sort.split("-") as ["name" | "date" | "size", "asc" | "desc"];
  const sign = dir === "asc" ? 1 : -1;
  const value = (row: GridRow): string | number | null =>
    field === "name" ? rowName(row) : field === "date" ? timeOf(row) : rowSize(row);
  return rows
    .map((row, index) => ({ row, index, v: value(row) }))
    .sort((a, b) => {
      if (a.v === null && b.v === null) return a.index - b.index;
      if (a.v === null) return 1;
      if (b.v === null) return -1;
      const cmp =
        typeof a.v === "string" ? a.v.localeCompare(String(b.v)) : (a.v as number) - (b.v as number);
      return cmp * sign || a.index - b.index;
    })
    .map((x) => x.row);
}

export interface GridKey {
  key: string;
  ctrlKey?: boolean;
  metaKey?: boolean;
}

/**
 * Next tile index for a key in a row-major grid of `count` tiles and `columns`
 * per row (ARIA grid pattern): arrows move one cell (Up/Down one row), Home /
 * End go to the first / last tile of the row, Ctrl+Home / Ctrl+End to the
 * first / last tile, PageUp / PageDown move `pageRows` rows. null = not a
 * navigation key.
 */
export function gridMove(
  index: number,
  event: GridKey,
  columns: number,
  count: number,
  pageRows = 3,
): number | null {
  if (count <= 0) return null;
  const cols = Math.max(1, columns);
  const last = count - 1;
  const clamp = (n: number) => Math.min(Math.max(n, 0), last);
  const rowStart = index - (index % cols);
  const ctrl = event.ctrlKey || event.metaKey;
  switch (event.key) {
    case "ArrowRight":
      return clamp(index + 1);
    case "ArrowLeft":
      return clamp(index - 1);
    case "ArrowDown":
      return index + cols <= last ? index + cols : index;
    case "ArrowUp":
      return index - cols >= 0 ? index - cols : index;
    case "Home":
      return ctrl ? 0 : rowStart;
    case "End":
      return ctrl ? last : Math.min(rowStart + cols - 1, last);
    case "PageDown":
      return clamp(index + cols * pageRows);
    case "PageUp":
      return clamp(index - cols * pageRows);
    default:
      return null;
  }
}

/**
 * Concurrency limiter: at most `max` tasks run at once; the rest wait in FIFO
 * order. A queued task whose signal aborts leaves the queue without running.
 */
export function createLimiter(max: number) {
  let active = 0;
  const queue: Array<() => void> = [];
  const next = () => {
    if (active >= max) return;
    const start = queue.shift();
    if (start) start();
  };
  return function limit<T>(signal: AbortSignal | undefined, task: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      if (signal?.aborted) {
        reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
        return;
      }
      const start = () => {
        signal?.removeEventListener("abort", onAbort);
        active += 1;
        task()
          .then(resolve, reject)
          .finally(() => {
            active -= 1;
            next();
          });
      };
      const onAbort = () => {
        const at = queue.indexOf(start);
        if (at >= 0) queue.splice(at, 1);
        reject(signal?.reason ?? new DOMException("Aborted", "AbortError"));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      queue.push(start);
      next();
    });
  };
}
