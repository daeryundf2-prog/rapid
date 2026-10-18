/**
 * 지도 대체 뷰 model (r4 §2.3): coordinates of a row and proximity clusters on a 0.01° grid.
 * No map tiles and no external map calls (policy) — the view is a coordinate table plus this
 * cluster list. `rowCoordinates` mirrors `rapidtriage/api/app/row_conditions.py`
 * `row_coordinates` (the server's `geo=` box filter reads the same fields).
 */

import type { GridRow } from "../../contracts/collection";
import { parseInstant } from "../../utils/time";

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

const round = (value: number) => Math.round(value * 1e6) / 1e6;

/**
 * Cell index of a coordinate (floor on the 0.01° grid; a tiny epsilon keeps 37.48 in cell 3748),
 * clamped so the box never passes the world edge: 90° / 180° fall in the last cell, whose upper
 * edge the server's half-open box includes (`row_conditions.in_geo_box`).
 */
function cell(value: number, limit: number): number {
  const last = Math.round(limit / CLUSTER_CELL_DEGREES) - 1;
  return Math.max(-last - 1, Math.min(last, Math.floor(value / CLUSTER_CELL_DEGREES + 1e-9)));
}

/** Proximity clusters: rows grouped by their 0.01° grid cell, most rows first. */
export function clusterRows(rows: readonly GeoRow[]): GeoCluster[] {
  const byCell = new Map<string, GeoCluster>();
  for (const item of rows) {
    const latCell = cell(item.lat, 90);
    const lonCell = cell(item.lon, 180);
    const id = `${latCell}:${lonCell}`;
    let cluster = byCell.get(id);
    if (!cluster) {
      const lat0 = round(latCell * CLUSTER_CELL_DEGREES);
      const lon0 = round(lonCell * CLUSTER_CELL_DEGREES);
      const lat1 = round(lat0 + CLUSTER_CELL_DEGREES);
      const lon1 = round(lon0 + CLUSTER_CELL_DEGREES);
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

/** "37.4812° N, 126.9497° E" (4 decimals ≈ 11 m). */
export function formatCoordinates(lat: number, lon: number): string {
  const ns = lat >= 0 ? "N" : "S";
  const ew = lon >= 0 ? "E" : "W";
  return `${Math.abs(lat).toFixed(4)}° ${ns}, ${Math.abs(lon).toFixed(4)}° ${ew}`;
}
