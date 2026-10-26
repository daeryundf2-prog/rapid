/**
 * Histogram model (S9, plan X15). Pure functions: re-bucket the server's
 * `timeline-histogram` buckets into hour/day bars, turn a bar selection into
 * an inclusive ISO range, and build category bars from the run tree or rows.
 */

import type { RunTree, TreeNode } from "../../api/runs";
import type { CollectionId, GridRow } from "../../contracts/collection";
import { uniqueLabels } from "../grid/columns/families";
import { typeDisplayLabel } from "../grid/valueLabels";

/** `GET /api/runs/{id}/timeline-histogram` (api/app/timeline_hist.py). */
export interface TimelineHistogramPayload {
  profile_version?: string;
  total_events: number;
  parsed_events: number;
  unparsed_events: number;
  bucket_seconds: number | null;
  bucket_count: number;
  range_start: string | null;
  range_end: string | null;
  /** Events outside the requested `from`/`to` (server-side range, R7 S1 re-review). */
  range_excluded_events?: number;
  /** The range the server applied (echo of the conditions). */
  range_filter?: unknown;
  max_bucket_count?: number;
  sources: Array<{ name: string; count: number }>;
  buckets: Array<{
    index: number;
    start: string;
    end: string;
    count: number;
    by_source?: Record<string, number>;
  }>;
}

export type Granularity = "hour" | "day" | "native";
export type GranularityChoice = "auto" | Granularity;

export interface TimeBucket {
  startMs: number;
  endMs: number;
  count: number;
}

const HOUR = 3_600_000;
const DAY = 86_400_000;
/** Hour bars up to three days of span, day bars up to ~13 months; wider spans keep the server buckets. */
export const HOUR_SPAN_LIMIT = 3 * DAY;
export const DAY_SPAN_LIMIT = 400 * DAY;

function parseMs(value: string | null | undefined): number | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

/** Non-empty extent of the server buckets (padding buckets with 0 events are ignored). */
export function occupiedSpan(payload: TimelineHistogramPayload): { startMs: number; endMs: number } | null {
  let start: number | null = null;
  let end: number | null = null;
  for (const bucket of payload.buckets) {
    if (!bucket.count) continue;
    const s = parseMs(bucket.start);
    const e = parseMs(bucket.end);
    if (s === null || e === null) continue;
    if (start === null || s < start) start = s;
    if (end === null || e > end) end = e;
  }
  return start === null || end === null ? null : { startMs: start, endMs: end };
}

/** Auto granularity: hour for ≤ 3 days, day for ≤ 400 days, else the server's own buckets. */
export function chooseGranularity(payload: TimelineHistogramPayload): Granularity {
  const span = occupiedSpan(payload);
  const bucketMs = (payload.bucket_seconds ?? 0) * 1000;
  if (!span) return "day";
  const width = span.endMs - span.startMs;
  if (width <= HOUR_SPAN_LIMIT && bucketMs <= HOUR) return "hour";
  if (width <= DAY_SPAN_LIMIT && bucketMs <= DAY) return "day";
  return "native";
}

/**
 * Re-aggregate the server buckets into hour/day bars (UTC boundaries), from
 * the first to the last non-empty bar with gaps filled by zero bars so the
 * axis stays linear. A requested granularity finer than the server bucket
 * falls back to the server buckets (it cannot be split).
 */
export function rebucket(
  payload: TimelineHistogramPayload,
  choice: GranularityChoice = "auto",
): { granularity: Granularity; buckets: TimeBucket[] } {
  let granularity: Granularity = choice === "auto" ? chooseGranularity(payload) : choice;
  const serverMs = (payload.bucket_seconds ?? 0) * 1000;
  const size = granularity === "hour" ? HOUR : granularity === "day" ? DAY : 0;
  if (size && serverMs > size) granularity = "native";
  if (granularity === "native" || !size) {
    const native: TimeBucket[] = [];
    for (const bucket of payload.buckets) {
      const s = parseMs(bucket.start);
      const e = parseMs(bucket.end);
      if (s !== null && e !== null) native.push({ startMs: s, endMs: e, count: bucket.count });
    }
    return { granularity: "native", buckets: trimEmpty(native) };
  }
  const counts = new Map<number, number>();
  for (const bucket of payload.buckets) {
    if (!bucket.count) continue;
    const s = parseMs(bucket.start);
    if (s === null) continue;
    const key = Math.floor(s / size) * size;
    counts.set(key, (counts.get(key) ?? 0) + bucket.count);
  }
  if (counts.size === 0) return { granularity, buckets: [] };
  const keys = [...counts.keys()];
  const first = Math.min(...keys);
  const last = Math.max(...keys);
  const buckets: TimeBucket[] = [];
  for (let at = first; at <= last; at += size) {
    buckets.push({ startMs: at, endMs: at + size, count: counts.get(at) ?? 0 });
  }
  return { granularity, buckets };
}

function trimEmpty(buckets: TimeBucket[]): TimeBucket[] {
  let start = 0;
  let end = buckets.length;
  while (start < end && !buckets[start]?.count) start += 1;
  while (end > start && !buckets[end - 1]?.count) end -= 1;
  return buckets.slice(start, end);
}

/** Inclusive ISO range covering bars a..b (any order): `to` = last bar end − 1 ms. */
export function rangeOf(
  buckets: readonly TimeBucket[],
  a: number,
  b: number,
): { from: string; to: string } | null {
  const lo = Math.max(0, Math.min(a, b));
  const hi = Math.min(buckets.length - 1, Math.max(a, b));
  const first = buckets[lo];
  const last = buckets[hi];
  if (!first || !last) return null;
  return { from: new Date(first.startMs).toISOString(), to: new Date(last.endMs - 1).toISOString() };
}

const pad = (n: number) => String(n).padStart(2, "0");

/** UTC label: day "2026-10-11", hour "10-11 14시", native "2026-10-11 14:00". */
export function bucketLabel(ms: number, granularity: Granularity): string {
  const d = new Date(ms);
  const date = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  if (granularity === "day") return date;
  if (granularity === "hour")
    return `${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}시`;
  return `${date} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

export function bucketAriaLabel(bucket: TimeBucket, granularity: Granularity): string {
  const from = bucketLabel(bucket.startMs, granularity === "day" ? "native" : granularity);
  const to = bucketLabel(bucket.endMs, granularity === "day" ? "native" : granularity);
  return `${from} ~ ${to} (UTC): ${bucket.count.toLocaleString("ko-KR")}건`;
}

// --- width-fitted, zone-aware bars (R7 L1, C-V2) -------------------------------------------------

/** One bar per this many pixels of the bar area (482 bars in 460 px was unreadable). */
export const BAR_PX = 4;
/** Bars when the width is unknown (not laid out yet, tests). */
export const DEFAULT_MAX_BARS = 240;

/** Bar widths tried from the finest, for "자동" (each at least the server bucket). */
const FIT_SIZES_MS = [
  HOUR,
  3 * HOUR,
  6 * HOUR,
  12 * HOUR,
  DAY,
  2 * DAY,
  7 * DAY,
  14 * DAY,
  30 * DAY,
  91 * DAY,
  365 * DAY,
];

/** How many bars fit `widthPx` (one per BAR_PX), DEFAULT_MAX_BARS when unknown. */
export function maxBarsFor(widthPx: number | null | undefined): number {
  if (!widthPx || !Number.isFinite(widthPx) || widthPx <= 0) return DEFAULT_MAX_BARS;
  return Math.max(1, Math.floor(widthPx / BAR_PX));
}

export interface FittedBars {
  granularity: Granularity;
  /** Bar width in ms. */
  sizeMs: number;
  buckets: TimeBucket[];
  /** Server buckets left out by the range (outside it). */
  clipped: boolean;
}

/**
 * Bars of the timeline histogram fitted to the width (C-V2): the server buckets inside the time
 * range condition (`[fromMs, untilMs)`; a bucket that straddles a bound is kept whole), merged
 * into the finest bar width that keeps the count ≤ `maxBars`, with bar edges on the display
 * zone's hours / days (`offsetMinutes`, minutes east of UTC at the first bar).
 */
export function fitBuckets(
  payload: TimelineHistogramPayload,
  options: {
    maxBars: number;
    offsetMinutes?: number;
    fromMs?: number | null;
    untilMs?: number | null;
    /** A chosen bar width (시간 / 일 / 원본 버킷) instead of the fitted one; never below the server bucket. */
    sizeMs?: number;
  },
): FittedBars {
  const offset = (options.offsetMinutes ?? 0) * 60_000;
  const from = options.fromMs ?? null;
  const until = options.untilMs ?? null;
  const serverMs = Math.max(1, (payload.bucket_seconds ?? 0) * 1000);
  const kept: TimeBucket[] = [];
  let clipped = false;
  for (const bucket of payload.buckets) {
    const s = parseMs(bucket.start);
    const e = parseMs(bucket.end);
    if (s === null || e === null) continue;
    if ((until !== null && s >= until) || (from !== null && e <= from)) {
      if (bucket.count) clipped = true;
      continue;
    }
    if (bucket.count) kept.push({ startMs: s, endMs: e, count: bucket.count });
  }
  if (kept.length === 0) return { granularity: "native", sizeMs: serverMs, buckets: [], clipped };
  const first = Math.min(...kept.map((b) => b.startMs));
  const last = Math.max(...kept.map((b) => b.endMs));
  const maxBars = Math.max(1, options.maxBars);
  const fits = (size: number) => {
    const origin = Math.floor((first + offset) / size) * size - offset;
    return Math.ceil((last - origin) / size) <= maxBars;
  };
  let size =
    options.sizeMs !== undefined
      ? Math.max(options.sizeMs, serverMs)
      : FIT_SIZES_MS.find((candidate) => candidate >= serverMs && fits(candidate));
  if (size === undefined) {
    // Wider than a year per bar, or a coarse server bucket: whole server buckets per bar.
    const per = Math.max(1, Math.ceil((last - first) / maxBars / serverMs));
    size = per * serverMs;
    while (!fits(size)) size += serverMs;
  }
  const origin = Math.floor((first + offset) / size) * size - offset;
  const count = Math.max(1, Math.ceil((last - origin) / size));
  const buckets: TimeBucket[] = Array.from({ length: count }, (_, index) => ({
    startMs: origin + index * size,
    endMs: origin + (index + 1) * size,
    count: 0,
  }));
  for (const bucket of kept) {
    const index = Math.min(count - 1, Math.max(0, Math.floor((bucket.startMs - origin) / size)));
    const target = buckets[index];
    if (target) target.count += bucket.count;
  }
  const granularity: Granularity = size === HOUR ? "hour" : size === DAY ? "day" : "native";
  return { granularity, sizeMs: size, buckets, clipped };
}

/** "막대 1시간" · "막대 6시간" · "막대 1일" · "막대 7일" · "막대 42분" — the width of one bar. */
export function barSizeLabel(sizeMs: number): string {
  if (sizeMs >= DAY && sizeMs % DAY === 0) return `막대 ${sizeMs / DAY}일`;
  if (sizeMs >= HOUR && sizeMs % HOUR === 0) return `막대 ${sizeMs / HOUR}시간`;
  return `막대 ${Math.max(1, Math.round(sizeMs / 60_000))}분`;
}

/** Wall-clock parts of `ms` at a fixed offset (minutes east of UTC). */
function wall(ms: number, offsetMinutes: number) {
  const d = new Date(ms + offsetMinutes * 60_000);
  return {
    date: `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`,
    md: `${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`,
    hour: pad(d.getUTCHours()),
    minute: pad(d.getUTCMinutes()),
  };
}

/** Bar label in the display zone: a day-or-wider bar "2026-10-11", an hour bar "10-11 14시", else "2026-10-11 14:00". */
export function zonedBucketLabel(ms: number, sizeMs: number, offsetMinutes: number): string {
  const w = wall(ms, offsetMinutes);
  if (sizeMs >= DAY) return w.date;
  if (sizeMs === HOUR) return `${w.md} ${w.hour}시`;
  return `${w.date} ${w.hour}:${w.minute}`;
}

/** "2026-10-11 14:00 ~ 2026-10-11 15:00 (KST+09:00): 6건". */
export function zonedBucketAriaLabel(bucket: TimeBucket, offsetMinutes: number, zone: string): string {
  const a = wall(bucket.startMs, offsetMinutes);
  const b = wall(bucket.endMs, offsetMinutes);
  return `${a.date} ${a.hour}:${a.minute} ~ ${b.date} ${b.hour}:${b.minute} (${zone}): ${bucket.count.toLocaleString("ko-KR")}건`;
}

export const GRANULARITY_LABELS: Record<GranularityChoice, string> = {
  auto: "자동",
  hour: "시간 단위",
  day: "일 단위",
  native: "원본 버킷",
};

// --- category bars ----------------------------------------------------------

export interface CategoryBar {
  id: string;
  label: string;
  count: number;
  /** Artifact kind node (click opens that node). */
  kind?: string;
  /** Artifact type (click filters `types`). */
  artifactType?: string;
  /** File extension (click filters `ext`). */
  extension?: string;
}

function findNode(nodes: readonly TreeNode[], match: (node: TreeNode) => boolean): TreeNode | null {
  for (const node of nodes) {
    if (match(node)) return node;
    const hit = node.children ? findNode(node.children, match) : null;
    if (hit) return hit;
  }
  return null;
}

/** Kind nodes below the artifacts root (group nodes are flattened), with their group's label. */
function kindNodes(nodes: readonly TreeNode[], group = ""): Array<{ node: TreeNode; group: string }> {
  const out: Array<{ node: TreeNode; group: string }> = [];
  for (const node of nodes) {
    if (node.kind && !node.artifact_type) out.push({ node, group });
    else if (node.children) out.push(...kindNodes(node.children, node.label));
  }
  return out;
}

/** Bars with unique labels (R7 L3, C-V1): a kind split over groups names its group. */
function distinct(bars: Array<CategoryBar & { context?: string }>): CategoryBar[] {
  return uniqueLabels(bars).map(({ context: _context, ...bar }) => bar);
}

const byCount = (a: CategoryBar, b: CategoryBar) => b.count - a.count || a.label.localeCompare(b.label);

/**
 * Artifact bars from GET /api/runs/{id}/tree: the artifacts root → one bar per
 * kind (click opens the kind node); a kind node → one bar per artifact_type.
 */
export function barsFromTree(tree: RunTree | undefined, kind: string | undefined): CategoryBar[] {
  if (!tree) return [];
  if (kind) {
    const node = findNode(tree.nodes, (n) => n.kind === kind && !n.artifact_type);
    const bars = (node?.children ?? [])
      .filter((c) => c.artifact_type)
      .map((c) => ({
        id: c.id,
        // The type's Korean name (never the raw id, C-D9); the node label when the type has none.
        label: c.artifact_type ? typeDisplayLabel(c.artifact_type) : c.label,
        count: c.count,
        artifactType: c.artifact_type,
      }))
      .sort(byCount);
    return distinct(bars);
  }
  const root = tree.nodes.find((n) => n.id === "artifacts" || (n.collection === "artifacts" && !n.kind));
  return distinct(
    kindNodes(root?.children ?? [])
      .map(({ node, group }) => ({
        id: node.id,
        label: node.label,
        count: node.count,
        kind: node.kind,
        context: group,
      }))
      .sort(byCount),
  );
}

function rowExt(row: GridRow): string {
  const field = row.fields.extension;
  if (typeof field === "string" && field) return field.replace(/^\.+/, "").toLowerCase();
  const match = /\.([A-Za-z0-9]{1,8})$/.exec(row.sourcePath ?? row.title);
  return match?.[1] ? match[1].toLowerCase() : "";
}

/** Bars over loaded rows: files by extension, other collections by artifact type. */
export function barsFromRows(rows: readonly GridRow[], collection: CollectionId | null): CategoryBar[] {
  const counts = new Map<string, number>();
  const byExtension = collection === "files";
  for (const row of rows) {
    const key = byExtension ? rowExt(row) : (row.artifactType ?? "");
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return distinct(
    [...counts.entries()]
      .map(([key, count]): CategoryBar => {
        const label = key ? typeDisplayLabel(key) : byExtension ? "(확장자 없음)" : "(유형 없음)";
        if (!key) return { id: `none`, label, count };
        return byExtension
          ? { id: `ext:${key}`, label: `.${key}`, count, extension: key }
          : { id: `type:${key}`, label, count, artifactType: key };
      })
      .sort(byCount),
  );
}
