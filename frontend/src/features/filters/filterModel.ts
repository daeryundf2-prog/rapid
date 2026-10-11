/**
 * Filter model (X19): pure state, URL mapping, server/client partitioning and
 * the client-side row predicate. No React, no stores.
 *
 * Server-capable filters (checked against the API, console-redesign S8):
 *  - artifacts: `path_contains` (path text), `kind=` (a single selected type)
 *  - search:    `extension` (repeated param)
 *  - timeline/files/docs/indicators: paging only, nothing server-side
 * Everything else (time range, review status, tags, extra types) runs on the
 * rows already loaded; the filter status line says so.
 */

import type { CollectionQuery, CollectionRef, GridRow, ReviewStatus } from "../../contracts/collection";
import type { Route } from "../../router";
import { parseInstant } from "../../utils/time";

export interface FilterState {
  /** Inclusive lower bound (ISO or `YYYY-MM-DDTHH:mm`). */
  from?: string;
  to?: string;
  statuses: ReviewStatus[];
  types: string[];
  tags: string[];
  /** Extensions, lower-case, no leading dot. */
  ext: string[];
  path: string;
}

export const EMPTY_FILTERS: FilterState = Object.freeze({
  statuses: [],
  types: [],
  tags: [],
  ext: [],
  path: "",
}) as FilterState;

export function normalizeExt(value: string): string {
  return value.trim().replace(/^\.+/, "").toLowerCase();
}

export function filtersFromRoute(route: Route): FilterState {
  return {
    ...(route.from ? { from: route.from } : {}),
    ...(route.to ? { to: route.to } : {}),
    statuses: route.statuses ?? [],
    types: route.types ?? [],
    tags: route.tags ?? [],
    ext: (route.ext ?? []).map(normalizeExt).filter(Boolean),
    path: route.path ?? "",
  };
}

/** Route patch for a filter state; empty parts are `undefined` so `patchRoute` clears them. */
export function filtersToRoutePatch(filters: FilterState): Partial<Route> {
  return {
    from: filters.from || undefined,
    to: filters.to || undefined,
    statuses: filters.statuses.length ? filters.statuses : undefined,
    types: filters.types.length ? filters.types : undefined,
    tags: filters.tags.length ? filters.tags : undefined,
    ext: filters.ext.length ? filters.ext : undefined,
    path: filters.path || undefined,
  };
}

export function filtersEqual(a: FilterState, b: FilterState): boolean {
  return (
    (a.from ?? "") === (b.from ?? "") &&
    (a.to ?? "") === (b.to ?? "") &&
    a.path === b.path &&
    a.statuses.join() === b.statuses.join() &&
    a.types.join() === b.types.join() &&
    a.tags.join() === b.tags.join() &&
    a.ext.join() === b.ext.join()
  );
}

export function hasActiveFilters(filters: FilterState): boolean {
  return !filtersEqual(filters, EMPTY_FILTERS);
}

// --- time presets -----------------------------------------------------------

export type TimePreset = "today" | "7d" | "30d";

export const TIME_PRESET_LABELS: Record<TimePreset, string> = {
  today: "오늘",
  "7d": "7일",
  "30d": "30일",
};

/** Local `YYYY-MM-DDTHH:mm` (the value format of `<input type="datetime-local">`). */
export function toLocalInput(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** Value for `<input type="datetime-local">` from any ISO bound (S10 clock buttons pass ISO with Z). */
export function toInputValue(value: string | undefined): string {
  if (!value) return "";
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) return value;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? "" : toLocalInput(new Date(ms));
}

export function presetRange(preset: TimePreset, now: Date = new Date()): { from: string; to: string } {
  const start = new Date(now);
  if (preset === "today") start.setHours(0, 0, 0, 0);
  else start.setTime(now.getTime() - (preset === "7d" ? 7 : 30) * 86_400_000);
  return { from: toLocalInput(start), to: toLocalInput(now) };
}

/** Which preset (if any) the current range equals, with a minute of slack. */
export function activePreset(filters: FilterState, now: Date = new Date()): TimePreset | null {
  if (!filters.from || !filters.to) return null;
  for (const preset of ["today", "7d", "30d"] as const) {
    const range = presetRange(preset, now);
    if (
      Math.abs(Date.parse(range.from) - Date.parse(filters.from)) <= 60_000 &&
      Math.abs(Date.parse(range.to) - Date.parse(filters.to)) <= 60_000
    )
      return preset;
  }
  return null;
}

// --- partitioning -----------------------------------------------------------

export interface FilterPlan {
  server: { path?: string; extension?: string[]; kind?: string };
  /** Korean names of filters the API applies. */
  serverLabels: string[];
  /** Korean names of filters applied only to loaded rows. */
  clientLabels: string[];
}

/** Decide which active filters go to the API for this collection and which stay on the client. */
export function partitionFilters(ref: CollectionRef, filters: FilterState): FilterPlan {
  const server: FilterPlan["server"] = {};
  const serverLabels: string[] = [];
  const clientLabels: string[] = [];

  if (filters.from || filters.to) clientLabels.push("시간 범위"); // no from/to on any API
  if (filters.statuses.length) clientLabels.push("상태");
  if (filters.tags.length) clientLabels.push("태그");

  if (filters.types.length) {
    if (ref.id === "artifacts" && !ref.kind && filters.types.length === 1) {
      server.kind = filters.types[0];
      serverLabels.push("유형");
    } else clientLabels.push("유형");
  }
  if (filters.ext.length) {
    if (ref.id === "search") {
      server.extension = filters.ext;
      serverLabels.push("확장자");
    } else clientLabels.push("확장자");
  }
  if (filters.path) {
    if (ref.id === "artifacts") {
      server.path = filters.path;
      serverLabels.push("경로");
    } else clientLabels.push("경로");
  }
  return { server, serverLabels, clientLabels };
}

/** The filters the client must still apply: those the API already handled are blanked out. */
export function clientOnlyFilters(filters: FilterState, plan: FilterPlan): FilterState {
  return {
    ...filters,
    types: plan.server.kind ? [] : filters.types,
    ext: plan.server.extension ? [] : filters.ext,
    path: plan.server.path ? "" : filters.path,
  };
}

/** Fold the filters into a query (server fields; paging untouched). */
export function applyFiltersToQuery(query: CollectionQuery, filters: FilterState): CollectionQuery {
  const plan = partitionFilters(query.ref, filters);
  const next: CollectionQuery = { ...query };
  if (filters.from || filters.to) next.timeRange = { from: filters.from, to: filters.to };
  if (filters.statuses.length) next.reviewStatus = filters.statuses;
  if (filters.tags.length) next.tags = filters.tags;
  if (filters.types.length) next.artifactTypes = filters.types;
  if (plan.server.path) next.pathContains = plan.server.path;
  if (plan.server.extension) next.extension = plan.server.extension;
  if (plan.server.kind) next.ref = { ...query.ref, kind: plan.server.kind };
  return next;
}

// --- client predicate --------------------------------------------------------

function parseTime(value: string | undefined | null): number | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

export function rowExtension(row: GridRow): string {
  const field = row.fields.extension;
  if (typeof field === "string" && field) return normalizeExt(field);
  const name = row.sourcePath ?? row.title;
  const match = /\.([A-Za-z0-9]{1,8})$/.exec(name);
  return match?.[1] ? match[1].toLowerCase() : "";
}

function rowKind(row: GridRow): string {
  const kind = row.fields.kind;
  return typeof kind === "string" ? kind : "";
}

/** True when the row passes every active filter (server-handled ones are re-checked; harmless). */
export function rowMatchesFilters(row: GridRow, filters: FilterState): boolean {
  const from = parseTime(filters.from);
  const to = parseTime(filters.to);
  if (from !== null || to !== null) {
    const at = parseInstant(row.timestamp)?.getTime() ?? null;
    if (at === null) return false;
    if (from !== null && at < from) return false;
    if (to !== null && at > to) return false;
  }
  if (filters.statuses.length) {
    const ok = filters.statuses.some((s) =>
      s === "include-in-report" ? row.fields.includeInReport === true : row.reviewStatus === s,
    );
    if (!ok) return false;
  }
  if (filters.types.length) {
    const type = (row.artifactType ?? "").toLowerCase();
    const kind = rowKind(row).toLowerCase();
    if (!filters.types.some((t) => t.toLowerCase() === type || t.toLowerCase() === kind)) return false;
  }
  if (filters.tags.length && !filters.tags.some((t) => row.tags.includes(t))) return false;
  if (filters.ext.length && !filters.ext.includes(rowExtension(row))) return false;
  if (filters.path && !(row.sourcePath ?? "").toLowerCase().includes(filters.path.toLowerCase()))
    return false;
  return true;
}

export function applyClientFilters(rows: GridRow[], filters: FilterState): GridRow[] {
  return hasActiveFilters(filters) ? rows.filter((row) => rowMatchesFilters(row, filters)) : rows;
}

// --- chips -------------------------------------------------------------------

export type FilterKey = "range" | "status" | "type" | "tag" | "ext" | "path";

export interface FilterChip {
  key: FilterKey;
  /** Item inside a multi-value filter (undefined for range/path). */
  value?: string;
  label: string;
}

export function activeChips(filters: FilterState, statusLabel: (s: ReviewStatus) => string): FilterChip[] {
  const chips: FilterChip[] = [];
  if (filters.from || filters.to) {
    chips.push({
      key: "range",
      label: `시간 ${filters.from ? filters.from.replace("T", " ") : "…"} ~ ${filters.to ? filters.to.replace("T", " ") : "…"}`,
    });
  }
  for (const s of filters.statuses) chips.push({ key: "status", value: s, label: `상태 ${statusLabel(s)}` });
  for (const t of filters.types) chips.push({ key: "type", value: t, label: `유형 ${t}` });
  for (const t of filters.tags) chips.push({ key: "tag", value: t, label: `태그 ${t}` });
  for (const e of filters.ext) chips.push({ key: "ext", value: e, label: `확장자 .${e}` });
  if (filters.path) chips.push({ key: "path", label: `경로 ${filters.path}` });
  return chips;
}

export function removeChip(filters: FilterState, chip: FilterChip): FilterState {
  switch (chip.key) {
    case "range":
      return { ...filters, from: undefined, to: undefined };
    case "status":
      return { ...filters, statuses: filters.statuses.filter((s) => s !== chip.value) };
    case "type":
      return { ...filters, types: filters.types.filter((t) => t !== chip.value) };
    case "tag":
      return { ...filters, tags: filters.tags.filter((t) => t !== chip.value) };
    case "ext":
      return { ...filters, ext: filters.ext.filter((e) => e !== chip.value) };
    case "path":
      return { ...filters, path: "" };
  }
}
