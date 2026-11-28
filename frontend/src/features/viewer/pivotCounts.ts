/**
 * Counts of the viewer's 함께 볼 것 pivots (design-viewer-keys F19): how many rows each of
 * ±5분 · 같은 대상 · 같은 원본 파일 opens, read from the same listing APIs the destination
 * grid uses. Lazy (only for the row on screen, after it settles), cancellable (an AbortSignal per
 * row) and cached per run, so J / K back and forth costs nothing.
 *
 *  - ±5분: `GET /timeline?from&to&limit=1` → `pagination.matched` (server row conditions).
 *  - 같은 대상: `GET /search?keyword=<value>&search_mode=exact&limit=1` → `summary.match_count`.
 *  - 같은 원본 파일: artifacts `path_contains` pages (server filter; counted up to a cap), the
 *    timeline by one capped scan per run that counts every source path at once (the timeline API
 *    has no path filter), files / docs by their own path.
 */

import { api } from "../../api/client";
import type { GridRow } from "../../contracts/collection";
import type { Route } from "../../router";
import { isRecord } from "../grid/columns/common";
import type { Pivot } from "./pivots";

export interface PivotCount {
  count: number;
  /** The count stopped at a cap: "n+" (more rows exist). */
  capped: boolean;
}

const enc = encodeURIComponent;

/** Rows counted per listing page; the cap is pages × this. */
export const COUNT_PAGE = 1000;
/** Pages a same-source count reads at most (artifacts: one kind; timeline: the whole run once). */
export const COUNT_MAX_PAGES = 10;

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

async function timelineWindowCount(runId: string, route: Route, signal: AbortSignal): Promise<PivotCount> {
  const params = new URLSearchParams({ offset: "0", limit: "1", view: "list" });
  if (route.from) params.set("from", route.from);
  if (route.to) params.set("to", route.to);
  const payload = await api<Record<string, unknown>>(`/api/runs/${enc(runId)}/timeline?${params}`, {
    signal,
  });
  const pagination = isRecord(payload.pagination) ? payload.pagination : {};
  const count = asNumber(pagination.matched) ?? asNumber(pagination.total) ?? asNumber(payload.matched) ?? 0;
  return { count, capped: false };
}

/** The search route's keywords as the search API takes them (quoted phrases stay one keyword). */
export function routeKeywords(q: string | undefined): string[] {
  const text = (q ?? "").trim();
  if (!text) return [];
  const quoted = /^"(.*)"$/.exec(text);
  return [quoted?.[1] ?? text];
}

async function searchCount(runId: string, route: Route, signal: AbortSignal): Promise<PivotCount | null> {
  const keywords = routeKeywords(route.q);
  if (keywords.length === 0) return null;
  const params = new URLSearchParams({ limit: "1", search_mode: "exact" });
  for (const keyword of keywords) params.append("keyword", keyword);
  const payload = await api<Record<string, unknown>>(`/api/runs/${enc(runId)}/search?${params}`, { signal });
  const summary = isRecord(payload.summary) ? payload.summary : {};
  const count = asNumber(summary.match_count);
  if (count === null) return null;
  return { count, capped: payload.truncated === true };
}

async function artifactPathCount(
  runId: string,
  kind: string,
  path: string,
  signal: AbortSignal,
): Promise<PivotCount> {
  let count = 0;
  for (let page = 0; page < COUNT_MAX_PAGES; page += 1) {
    const params = new URLSearchParams({
      kind,
      path_contains: path,
      offset: String(page * COUNT_PAGE),
      limit: String(COUNT_PAGE),
      view: "list",
    });
    const payload = await api<{ artifacts?: Record<string, Record<string, unknown>> }>(
      `/api/runs/${enc(runId)}/artifacts?${params}`,
      { signal },
    );
    const kindPage = payload.artifacts?.[kind] ?? {};
    const pagination = isRecord(kindPage.pagination) ? kindPage.pagination : {};
    const matched = asNumber(pagination.matched);
    if (matched !== null) return { count: matched, capped: false };
    const rows = Array.isArray(kindPage.artifacts) ? kindPage.artifacts.length : 0;
    count += rows;
    if (pagination.has_more !== true || rows === 0) return { count, capped: false };
  }
  return { count, capped: true };
}

/** One capped scan of the run's timeline: events per source path. */
interface PathTally {
  counts: Map<string, number>;
  capped: boolean;
}

const timelineTallies = new Map<string, Promise<PathTally>>();

async function scanTimelinePaths(runId: string, signal: AbortSignal): Promise<PathTally> {
  const counts = new Map<string, number>();
  for (let page = 0; page < COUNT_MAX_PAGES; page += 1) {
    const params = new URLSearchParams({
      offset: String(page * COUNT_PAGE),
      limit: String(COUNT_PAGE),
      view: "list",
    });
    const payload = await api<Record<string, unknown>>(`/api/runs/${enc(runId)}/timeline?${params}`, {
      signal,
    });
    const events = Array.isArray(payload.events) ? payload.events : [];
    for (const event of events) {
      const path = isRecord(event) && typeof event.path === "string" ? event.path : "";
      if (path) counts.set(path, (counts.get(path) ?? 0) + 1);
    }
    const pagination = isRecord(payload.pagination) ? payload.pagination : {};
    if (pagination.has_more !== true || events.length === 0) return { counts, capped: false };
  }
  return { counts, capped: true };
}

async function timelinePathCount(runId: string, path: string, signal: AbortSignal): Promise<PivotCount> {
  let pending = timelineTallies.get(runId);
  if (!pending) {
    // One shared scan per run; it is not tied to the row that asked first (a J press must not
    // abort the scan the next row also needs).
    pending = scanTimelinePaths(runId, new AbortController().signal);
    timelineTallies.set(runId, pending);
    pending.catch(() => timelineTallies.delete(runId));
  }
  const tally = await raceAbort(pending, signal);
  return { count: tally.counts.get(path) ?? 0, capped: tally.capped };
}

function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new DOMException("aborted", "AbortError"));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new DOMException("aborted", "AbortError"));
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

/** Rows the pivot's route opens; null when no API can count them (the button still works). */
export async function countPivot(
  pivot: Pivot,
  row: GridRow,
  runId: string,
  signal: AbortSignal,
): Promise<PivotCount | null> {
  const route = pivot.route;
  if (!route) return null;
  switch (pivot.id) {
    case "timeline-window":
      return timelineWindowCount(runId, route, signal);
    case "same-target":
      return route.collection === "search" ? searchCount(runId, route, signal) : null;
    case "same-source": {
      const path = route.path ?? row.sourcePath ?? "";
      if (!path) return null;
      if (route.collection === "artifacts" && route.kind)
        return artifactPathCount(runId, route.kind, path, signal);
      if (route.collection === "timeline") return timelinePathCount(runId, path, signal);
      return null;
    }
    default:
      return null;
  }
}

/** Finished counts per (run, pivot, value): J / K back to a row shows them at once. */
const cache = new Map<string, PivotCount | null>();
const CACHE_MAX = 500;

export function pivotCountKey(runId: string, pivot: Pivot): string {
  return `${runId}|${pivot.id}|${JSON.stringify(pivot.route ?? null)}`;
}

export function cachedPivotCount(key: string): PivotCount | null | undefined {
  return cache.get(key);
}

export function rememberPivotCount(key: string, value: PivotCount | null): void {
  if (cache.size >= CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(key, value);
}

/** Tests: forget cached counts and timeline scans. */
export function resetPivotCounts(): void {
  cache.clear();
  timelineTallies.clear();
}

/** "1,234건" · "10,000+건". */
export function pivotCountText(count: PivotCount): string {
  return `${count.count.toLocaleString("ko-KR")}${count.capped ? "+" : ""}건`;
}
