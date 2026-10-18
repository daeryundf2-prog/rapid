/**
 * Value rules of the row conditions (r4 §2.3) shared by the router (URL), the condition memory
 * (saved sets) and the filter model — kept free of router / store imports so every one of them
 * can use it. Keep aligned with `rapidtriage/api/app/row_conditions.py` (parse_hours, parse_geo,
 * parse_weekdays, CONTENT_TYPES).
 */

import { CONTENT_TYPE_IDS } from "./contentTypes";

/** Monday-first weekday ids (URL `wd=`, server `weekday=`). */
export const WEEKDAY_IDS: readonly string[] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/** `HH-HH` → [start, end] (0–23), null when malformed or empty (start = end). */
export function parseHours(value: string | undefined): [number, number] | null {
  const match = /^(\d{1,2})-(\d{1,2})$/.exec(value ?? "");
  if (!match) return null;
  const start = Number(match[1]);
  const end = Number(match[2]);
  if (start > 24 || end > 24 || start % 24 === end % 24) return null;
  return [start % 24, end % 24];
}

/** Canonical `HH-HH` of a valid hours window, undefined otherwise. */
export function normalizeHours(value: unknown): string | undefined {
  const window = typeof value === "string" ? parseHours(value) : null;
  return window ? `${String(window[0]).padStart(2, "0")}-${String(window[1]).padStart(2, "0")}` : undefined;
}

/**
 * `lat_min,lon_min,lat_max,lon_max` → numbers, null unless the server would accept it: latitudes
 * -90..90 with min < max, longitudes -180..180 and different (min > max = across the antimeridian).
 */
export function parseGeo(value: string | undefined): [number, number, number, number] | null {
  if (!value) return null;
  const parts = value.split(",").map((part) => (part.trim() === "" ? Number.NaN : Number(part)));
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n))) return null;
  const [lat0, lon0, lat1, lon1] = parts as [number, number, number, number];
  if (!(lat0 >= -90 && lat0 < lat1 && lat1 <= 90)) return null;
  if (!(lon0 >= -180 && lon0 <= 180 && lon1 >= -180 && lon1 <= 180) || lon0 === lon1) return null;
  return [lat0, lon0, lat1, lon1];
}

function inSpan(value: number, low: number, high: number, limit: number): boolean {
  return low <= value && (value < high || (high === limit && value <= high));
}

/**
 * The point in the box (server `row_conditions.in_geo_box`): lower edges inclusive, upper edges
 * exclusive except at 90 / 180; `lon_min > lon_max` crosses the antimeridian.
 */
export function inGeoBox(
  point: { lat: number; lon: number },
  [lat0, lon0, lat1, lon1]: readonly [number, number, number, number],
): boolean {
  if (!inSpan(point.lat, lat0, lat1, 90)) return false;
  if (lon0 < lon1) return inSpan(point.lon, lon0, lon1, 180);
  return point.lon >= lon0 || point.lon < lon1;
}

/** Known weekday ids of a list, Monday first, without duplicates (unknown ids dropped). */
export function normalizeWeekdays(values: readonly unknown[]): string[] {
  return WEEKDAY_IDS.filter((day) => values.includes(day));
}

/** Known 콘텐츠 유형 ids of a list, in catalogue order (unknown ids dropped). */
export function normalizeContent(values: readonly unknown[]): string[] {
  return CONTENT_TYPE_IDS.filter((id) => values.includes(id));
}
