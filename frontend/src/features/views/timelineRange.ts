/**
 * Timeline overview strip model (fe-audit A1/A2). Pure: the bars of the strip above the
 * timeline grid (the whole span, or the zoomed range at a finer unit), range pan / zoom-out
 * steps, a window around an instant, and the time a user types to jump to.
 *
 * Ranges are inclusive `[fromMs, toMs]` like the filter bar's `from`/`to` (histogram
 * `rangeOf`: `to` = last bar end − 1 ms). Typed times are browser-local, like the range inputs.
 */

import {
  DAY_SPAN_LIMIT,
  type Granularity,
  rebucket,
  type TimeBucket,
  type TimelineHistogramPayload,
} from "./histogram";

export interface MsRange {
  fromMs: number;
  toMs: number;
}

const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
/** A zoomed range up to this width is drawn in hour bars, wider in day bars. */
const HOUR_BARS_UP_TO = 3 * DAY;
/** Default window of "이 시각 전후" (palette, row command). */
export const AROUND_HALF_MS = 30 * MINUTE;
/** Zoom-out factor of one `-` step. */
const ZOOM_OUT = 3;

function parseMs(value: string | null | undefined): number | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

/** The span the histogram covers (first bucket start .. last bucket end − 1 ms). */
export function extentOf(payload: TimelineHistogramPayload): MsRange | null {
  const { buckets } = rebucket(payload, "native");
  const first = buckets[0];
  const last = buckets.at(-1);
  return first && last ? { fromMs: first.startMs, toMs: last.endMs - 1 } : null;
}

/** The route's `from`/`to` as a range; an open bound takes the extent's edge. */
export function rangeFromBounds(
  from: string | undefined,
  to: string | undefined,
  extent: MsRange | null,
): MsRange | null {
  const fromMs = parseMs(from) ?? (to ? extent?.fromMs : undefined);
  const toMs = parseMs(to) ?? (from ? extent?.toMs : undefined);
  return fromMs === undefined || toMs === undefined || toMs < fromMs ? null : { fromMs, toMs };
}

/**
 * Bars of the strip. Without a range: the whole timeline (`payload` = the run's histogram) in
 * hour bars up to 3 days when the server buckets are ≤ 1 h, else day bars on local midnights
 * (the grid shows local time), empty bars kept so the axis stays linear; spans past ~13 months
 * keep the server buckets. With a range, `payload` is the histogram of that window
 * (`GET …/timeline-histogram?from=&to=`, finer server buckets) and its buckets are the bars.
 */
export function stripBars(
  payload: TimelineHistogramPayload,
  range: MsRange | null,
  extent: MsRange | null,
): { granularity: Granularity; buckets: TimeBucket[] } {
  if (range) {
    const buckets = rebucket(payload, "native").buckets.filter(
      (bucket) => bucket.endMs > range.fromMs && bucket.startMs <= range.toMs,
    );
    return { granularity: "native", buckets };
  }
  if (!extent) return { granularity: "day", buckets: [] };
  if (extent.toMs - extent.fromMs > DAY_SPAN_LIMIT) return rebucket(payload, "native");
  const serverMs = (payload.bucket_seconds ?? 0) * 1000;
  const size = extent.toMs - extent.fromMs < HOUR_BARS_UP_TO && serverMs <= HOUR ? HOUR : DAY;
  const start = new Date(extent.fromMs);
  if (size === DAY) start.setHours(0, 0, 0, 0);
  const first = size === DAY ? start.getTime() : Math.floor(extent.fromMs / HOUR) * HOUR;
  const buckets: TimeBucket[] = [];
  for (let at = first; at <= extent.toMs; at += size)
    buckets.push({ startMs: at, endMs: at + size, count: 0 });
  for (const bucket of payload.buckets) {
    const at = parseMs(bucket.start);
    if (at === null || !bucket.count || at < first) continue;
    const slot = buckets[Math.floor((at - first) / size)];
    if (slot) slot.count += bucket.count;
  }
  return { granularity: size === HOUR ? "hour" : "day", buckets };
}

/** The same-width range before (−1) or after (+1), kept inside the extent. */
export function panRange(range: MsRange, direction: -1 | 1, extent: MsRange): MsRange {
  const width = range.toMs - range.fromMs;
  let fromMs = range.fromMs + direction * (width + 1);
  fromMs = Math.min(Math.max(fromMs, extent.fromMs), Math.max(extent.toMs - width, extent.fromMs));
  return { fromMs, toMs: fromMs + width };
}

/** Three times the width around the same centre; null when that covers the whole extent (= clear). */
export function zoomOutRange(range: MsRange, extent: MsRange): MsRange | null {
  const grow = ((range.toMs - range.fromMs + 1) * (ZOOM_OUT - 1)) / 2;
  const fromMs = Math.max(extent.fromMs, Math.floor(range.fromMs - grow));
  const toMs = Math.min(extent.toMs, Math.ceil(range.toMs + grow));
  return fromMs <= extent.fromMs && toMs >= extent.toMs ? null : { fromMs, toMs };
}

export function windowAround(ms: number, halfMs: number = AROUND_HALF_MS): MsRange {
  return { fromMs: ms - halfMs, toMs: ms + halfMs - 1 };
}

export function toIsoBounds(range: MsRange): { from: string; to: string } {
  return { from: new Date(range.fromMs).toISOString(), to: new Date(range.toMs).toISOString() };
}

export interface JumpTime {
  ms: number;
  /** A date alone means the whole (local) day; a clock time means "around this instant". */
  precision: "day" | "minute";
}

const JUMP_PATTERN = /^(\d{4})[-./](\d{1,2})[-./](\d{1,2})(?:[ T](\d{1,2})(?::(\d{2}))?(?::(\d{2}))?)?$/;

/** `2026-04-18`, `2026-04-18 14`, `2026.4.18 14:30`, `2026-04-18T14:30:05` (browser-local); else null. */
export function parseJumpTime(text: string): JumpTime | null {
  const match = JUMP_PATTERN.exec(text.trim());
  if (!match) return null;
  const [, y, mo, d, h, mi, s] = match.map((part) => (part === undefined ? undefined : Number(part)));
  if (y === undefined || mo === undefined || d === undefined) return null;
  const date = new Date(y, mo - 1, d, h ?? 0, mi ?? 0, s ?? 0);
  const valid =
    date.getFullYear() === y &&
    date.getMonth() === mo - 1 &&
    date.getDate() === d &&
    (h === undefined || date.getHours() === h) &&
    (mi === undefined || mi < 60) &&
    (s === undefined || s < 60);
  if (!valid) return null;
  return { ms: date.getTime(), precision: h === undefined ? "day" : "minute" };
}

/** The range a typed time opens: its local day, or ±30 min around the instant. */
export function jumpRange(jump: JumpTime): MsRange {
  return jump.precision === "day" ? { fromMs: jump.ms, toMs: jump.ms + DAY - 1 } : windowAround(jump.ms);
}
