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
