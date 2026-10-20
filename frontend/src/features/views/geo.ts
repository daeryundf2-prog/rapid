/**
 * 지도 대체 뷰 model (r4 §2.3): coordinates of a row and proximity clusters on a 0.01° grid.
 * No map tiles and no external map calls (policy) — the view is a coordinate table plus this
 * cluster list. `rowCoordinates` mirrors `rapidtriage/api/app/row_conditions.py`
 * `row_coordinates` (the server's `geo=` box filter reads the same fields).
 */

import { api } from "../../api/client";
import { artifactsQueryString, type TreeNode } from "../../api/runs";
import type { CollectionQuery, GridRow } from "../../contracts/collection";
import { parseInstant } from "../../utils/time";
import { serverPathFilter } from "../grid/gridUtils";
import { kindsForCategory } from "../tree/categories";

export const CLUSTER_CELL_DEGREES = 0.01;

const COORDINATE_KEYS: ReadonlyArray<[string, string]> = [
  ["gps_latitude", "gps_longitude"],
  ["latitude", "longitude"],
  ["lat", "lon"],
  ["lat", "lng"],
];

export interface Coordinates {
  lat: number;
  lon: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function numberOf(value: unknown): number | null {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string" && value.trim() !== "") {
    const number = Number(value.trim());
    return Number.isFinite(number) ? number : null;
  }
  return null;
}

/** `(lat, lon)` of a row; (0, 0) and out-of-range values count as none. */
export function rowCoordinates(row: GridRow): Coordinates | null {
  const details = isRecord(row.fields.details) ? row.fields.details : {};
  const containers: Record<string, unknown>[] = [details];
  if (isRecord(details.exif_gps_profile)) containers.push(details.exif_gps_profile);
  containers.push(row.fields);
  for (const container of containers) {
    for (const [latKey, lonKey] of COORDINATE_KEYS) {
      const lat = numberOf(container[latKey]);
      const lon = numberOf(container[lonKey]);
      if (lat === null || lon === null) continue;
      if (lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 && !(lat === 0 && lon === 0)) {
        return { lat, lon };
      }
    }
  }
  return null;
}

/** The GPS time of an EXIF row (`gps_timestamp` / `gps_datetime_utc_candidate`), else the row time. */
export function rowGeoTime(row: GridRow): string | null {
  const details = isRecord(row.fields.details) ? row.fields.details : {};
  const gps = isRecord(details.exif_gps_profile) ? details.exif_gps_profile : {};
  for (const value of [details.gps_timestamp, gps.gps_datetime_utc_candidate, row.timestamp]) {
    if (typeof value === "string" && parseInstant(value)) return value;
  }
  return null;
}

export interface GeoRow {
  row: GridRow;
  lat: number;
  lon: number;
  time: string | null;
}

export interface GeoCluster {
  /** `"<lat cell>:<lon cell>"` (integer cell indices). */
  id: string;
  /** Box of the cell: `lat0,lon0,lat1,lon1` (the server `geo=` value). */
  box: string;
  /** Cell centre (rounded to the grid). */
  lat: number;
  lon: number;
  count: number;
  first: string | null;
  last: string | null;
  rows: GridRow[];
}

export function geoRows(rows: readonly GridRow[]): GeoRow[] {
  const out: GeoRow[] = [];
  for (const row of rows) {
    const point = rowCoordinates(row);
    if (point) out.push({ row, lat: point.lat, lon: point.lon, time: rowGeoTime(row) });
  }
  return out;
}

/** `Math.round(value * 1e6) / 1e6` (server `geo_index._js_round6`). */
const round = (value: number) => Math.round(value * 1e6) / 1e6;

const lastCell = (limit: number, cell: number) => Math.round(limit / cell) - 1;

/**
 * Lower edge of cell `index` (the upper edge of `index - 1`), server `geo_index.cell_edge`:
 * `round6(index * cell)`, exactly `-limit` for the first cell and `limit` past the last
 * (clamped) one.
 */
export function cellEdge(index: number, limit: number, cell = CLUSTER_CELL_DEGREES): number {
  const last = lastCell(limit, cell);
  if (index <= -last - 1) return -limit;
  if (index > last) return limit;
  return round(index * cell);
}

/**
 * Grid cell index of a coordinate, server `geo_index.cell_of`: the cell whose half-open box
 * `[edge(i), edge(i + 1))` holds it (`limit` itself in the last cell, whose upper edge the
 * half-open box includes — `row_conditions.in_geo_box`), clamped to the first / last cell.
 */
export function cellOf(value: number, limit: number, cell = CLUSTER_CELL_DEGREES): number {
  const last = lastCell(limit, cell);
  let index = Math.max(-last - 1, Math.min(last, Math.floor(value / cell)));
  while (index > -last - 1 && value < cellEdge(index, limit, cell)) index -= 1;
  while (index < last && value >= cellEdge(index + 1, limit, cell)) index += 1;
  return index;
}

/** Proximity clusters: rows grouped by their 0.01° grid cell, most rows first. */
export function clusterRows(rows: readonly GeoRow[]): GeoCluster[] {
  const byCell = new Map<string, GeoCluster>();
  for (const item of rows) {
    const latCell = cellOf(item.lat, 90);
    const lonCell = cellOf(item.lon, 180);
    const id = `${latCell}:${lonCell}`;
    let cluster = byCell.get(id);
    if (!cluster) {
      const lat0 = cellEdge(latCell, 90);
      const lon0 = cellEdge(lonCell, 180);
      const lat1 = cellEdge(latCell + 1, 90);
      const lon1 = cellEdge(lonCell + 1, 180);
      cluster = {
        id,
        box: `${lat0},${lon0},${lat1},${lon1}`,
        lat: round(lat0 + CLUSTER_CELL_DEGREES / 2),
        lon: round(lon0 + CLUSTER_CELL_DEGREES / 2),
        count: 0,
        first: null,
        last: null,
        rows: [],
      };
      byCell.set(id, cluster);
    }
    cluster.count += 1;
    cluster.rows.push(item.row);
    const at = item.time ? (parseInstant(item.time)?.getTime() ?? null) : null;
    if (at !== null && item.time) {
      if (!cluster.first || at < (parseInstant(cluster.first)?.getTime() ?? Number.POSITIVE_INFINITY))
        cluster.first = item.time;
      if (!cluster.last || at > (parseInstant(cluster.last)?.getTime() ?? Number.NEGATIVE_INFINITY))
        cluster.last = item.time;
    }
  }
  return [...byCell.values()].sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
}

/** One cluster of `GET /api/runs/{id}/geo-clusters` (server cell rule = `clusterRows`). */
export interface ServerGeoCluster {
  id: string;
  box: string;
  lat: number;
  lon: number;
  count: number;
  first_time: string | null;
  last_time: string | null;
  sample?: { kind: string; record_index: number; lat: number; lon: number; time: string | null };
}

/**
 * `GET /geo-clusters` (r6 §3.3 갈래 C): clusters from the run's located-row index.
 * `geo_index`: `ready`, `building` (an older run's index is being built: ask again) or
 * `unavailable` (the console then clusters the loaded rows itself).
 */
export interface GeoClustersPayload {
  geo_index: "ready" | "building" | "unavailable";
  geo_index_source?: "file" | "built" | "memory";
  cell: number;
  kinds: string[];
  available_kinds: string[];
  located_total: number | null;
  matched: number | null;
  clusters: ServerGeoCluster[];
  clusters_total: number;
  clusters_truncated: boolean;
  truncated: boolean;
  filtered: boolean;
}

/**
 * The text filter `q` is only partly applied by the server: `/geo-clusters` (like the listing)
 * sends it as `path_contains` only when it is one word and no 경로 filter takes that parameter;
 * otherwise the console matches it on loaded rows and the server clusters cannot reflect it.
 */
export function geoTextFilterClientSide(query: CollectionQuery): boolean {
  const text = query.text?.trim();
  if (!text) return false;
  return Boolean(query.pathContains?.trim()) || serverPathFilter(text) === undefined;
}

/** The `/geo-clusters` filters of an artifacts collection query (the same server filters as its listing). */
export function geoClusterParams(query: CollectionQuery, kinds?: readonly string[]): string {
  const params = new URLSearchParams(
    artifactsQueryString({
      kind: kinds ? [...kinds] : query.ref.kind ? [query.ref.kind] : undefined,
      path_contains: query.pathContains?.trim() || serverPathFilter(query.text),
      artifact_type: query.artifactTypes,
      flag: query.flags,
      flag_grade: query.flagGrade,
      browser: query.fields?.browser ? [...query.fields.browser] : undefined,
      service: query.fields?.service ? [...query.fields.service] : undefined,
      channel: query.channels,
      channel_group: query.channelGroups,
      conditions: query.rowConditions,
    }),
  );
  params.set("cell", String(CLUSTER_CELL_DEGREES));
  return params.toString();
}

/** The run's artifact kinds as the tree lists them (`artifacts` nodes with a `kind`). */
export function artifactKindsOfTree(nodes: readonly TreeNode[] | undefined): string[] {
  const found = new Set<string>();
  const visit = (list: readonly TreeNode[] | undefined) => {
    for (const node of list ?? []) {
      if (node.collection === "artifacts" && node.kind) found.add(node.kind);
      visit(node.children);
    }
  };
  visit(nodes);
  return [...found].sort();
}

/** A category none of the run's kinds belong to: nothing to cluster. */
const EMPTY_CATEGORY = (available: readonly string[], cell = CLUSTER_CELL_DEGREES): GeoClustersPayload => ({
  geo_index: "ready",
  cell,
  kinds: [],
  available_kinds: [...available],
  located_total: 0,
  matched: 0,
  clusters: [],
  clusters_total: 0,
  clusters_truncated: false,
  truncated: false,
  filtered: false,
});

/**
 * Server clusters of the query's node. A category node sends its kinds — `kindsForCategory`
 * over the run's kinds from the tree (`runKinds`, as the listing does) — in one request; only
 * without the tree (`runKinds` null / empty) does it ask once for the run's kinds
 * (`available_kinds`) and again with the category's kinds.
 */
export async function fetchGeoClusters(
  runId: string,
  query: CollectionQuery,
  signal?: AbortSignal,
  runKinds?: readonly string[] | null,
): Promise<GeoClustersPayload> {
  const url = (kinds?: readonly string[]) =>
    `/api/runs/${encodeURIComponent(runId)}/geo-clusters?${geoClusterParams(query, kinds)}`;
  const category = !query.ref.kind ? query.ref.category : undefined;
  if (!category) return api<GeoClustersPayload>(url(), { signal });
  if (runKinds && runKinds.length > 0) {
    const kinds = kindsForCategory(category, runKinds);
    if (kinds.length === 0) return EMPTY_CATEGORY(runKinds);
    return api<GeoClustersPayload>(url(kinds), { signal });
  }
  const payload = await api<GeoClustersPayload>(url(), { signal });
  if (payload.geo_index !== "ready") return payload;
  const kinds = kindsForCategory(category, payload.available_kinds ?? []);
  if (kinds.length === 0) return EMPTY_CATEGORY(payload.available_kinds ?? [], payload.cell);
  return api<GeoClustersPayload>(url(kinds), { signal });
}

/** Server clusters in the console's cluster shape (rows stay on the server: `rows` is empty). */
export function serverClusters(payload: GeoClustersPayload): GeoCluster[] {
  return payload.clusters.map((cluster) => ({
    id: cluster.id,
    box: cluster.box,
    lat: cluster.lat,
    lon: cluster.lon,
    count: cluster.count,
    first: cluster.first_time,
    last: cluster.last_time,
    rows: [],
  }));
}

/** "37.4812° N, 126.9497° E" (4 decimals ≈ 11 m). */
export function formatCoordinates(lat: number, lon: number): string {
  const ns = lat >= 0 ? "N" : "S";
  const ew = lon >= 0 ? "E" : "W";
  return `${Math.abs(lat).toFixed(4)}° ${ns}, ${Math.abs(lon).toFixed(4)}° ${ew}`;
}
