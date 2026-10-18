/**
 * Row conditions (r4 §2.3 V3 필터): 요일 · 시간대 · 업무 외 시간 · 부분 결과 · 콘텐츠 유형 ·
 * 위치 상자, plus the relative time ranges of the date popover. Pure helpers: the server params
 * (`/artifacts`, `/files`, `/timeline`: `weekday=` `hours=` `offhours=` `tz=` `partial=`
 * `content=` `geo=` `from=` `to=`) and the client predicates for the other listings / views.
 * Keep aligned with `rapidtriage/api/app/row_conditions.py`.
 */

import type { GridRow } from "../../contracts/collection";
import { WEEKDAY_IDS } from "../../router";
import { parseInstant, zoneName } from "../../utils/time";
import { rowCoordinates } from "../views/geo";
import { rowContentTypes } from "./contentTypes";

export const WEEKDAY_LABELS: Readonly<Record<string, string>> = {
  mon: "월",
  tue: "화",
  wed: "수",
  thu: "목",
  fri: "금",
  sat: "토",
  sun: "일",
};
/** 업무 외 시간 defaults: 18:00–08:59 and the weekend. */
export const DEFAULT_OFFHOURS = "18-09";
export const DEFAULT_WEEKEND: readonly string[] = ["sat", "sun"];

export interface ClockConditions {
  weekdays?: readonly string[];
  hours?: string;
  offhours?: boolean;
}

/** `HH-HH` → [start, end] (0–23), null when malformed or empty (start = end). */
export function parseHours(value: string | undefined): [number, number] | null {
  const match = /^(\d{1,2})-(\d{1,2})$/.exec(value ?? "");
  if (!match) return null;
  const start = Number(match[1]);
  const end = Number(match[2]);
  if (start > 24 || end > 24 || start % 24 === end % 24) return null;
  return [start % 24, end % 24];
}

export function inHours(hour: number, [start, end]: [number, number]): boolean {
  return start < end ? hour >= start && hour < end : hour >= start || hour < end;
}

/** Monday-first weekday id and hour of an instant in a display timezone. */
export function localClock(date: Date, tz: string): { weekday: string; hour: number } {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: zoneName(tz),
    weekday: "short",
    hour: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);
  const weekday = (parts.find((p) => p.type === "weekday")?.value ?? "").slice(0, 3).toLowerCase();
  const hour = Number(parts.find((p) => p.type === "hour")?.value ?? 0) % 24;
  return { weekday, hour };
}

export function hasClock(conditions: ClockConditions): boolean {
  return Boolean(conditions.offhours || conditions.weekdays?.length || parseHours(conditions.hours));
}

/** The server's rule (row_conditions.RowConditions._clock_matches). */
export function clockMatches(date: Date, conditions: ClockConditions, tz: string): boolean {
  const { weekday, hour } = localClock(date, tz);
  const window = parseHours(conditions.hours);
  if (conditions.offhours) {
    const days = conditions.weekdays?.length ? conditions.weekdays : DEFAULT_WEEKEND;
    return (
      days.includes(weekday) || inHours(hour, window ?? (parseHours(DEFAULT_OFFHOURS) as [number, number]))
    );
  }
  if (conditions.weekdays?.length && !conditions.weekdays.includes(weekday)) return false;
  return !window || inHours(hour, window);
}

/** Korean chip label of the clock conditions ("업무 외 시간 18–09시·토·일", "요일 월·화", "시간 09–18시"). */
export function clockLabel(conditions: ClockConditions): string {
  const days = (conditions.weekdays ?? []).map((day) => WEEKDAY_LABELS[day] ?? day);
  const window = parseHours(conditions.hours);
  const hoursText = (w: [number, number]) =>
    `${String(w[0]).padStart(2, "0")}–${String(w[1]).padStart(2, "0")}시`;
  if (conditions.offhours) {
    const offWindow = window ?? (parseHours(DEFAULT_OFFHOURS) as [number, number]);
    const offDays = days.length ? days : DEFAULT_WEEKEND.map((day) => WEEKDAY_LABELS[day]);
    return `업무 외 시간 ${hoursText(offWindow)}·${offDays.join("·")}`;
  }
  return [days.length ? `요일 ${days.join("·")}` : "", window ? `시간 ${hoursText(window)}` : ""]
    .filter(Boolean)
    .join(" · ");
}

// --- 부분 결과 ------------------------------------------------------------------------------

const PARTIAL_STATUS_TOKENS = [
  "fail",
  "error",
  "truncat",
  "invalid",
  "not-recognized",
  "not-decoded",
  "unreadable",
  "too_large",
  "too-large",
  "unavailable",
  "corrupt",
  "partial",
];
const PARTIAL_TYPE_TOKENS = ["invalid", "unreadable", "parse-error", "parser-error"];
const DECRYPT_OK = new Set(["", "success", "decrypted", "not-applicable", "not-required", "not-encrypted"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function partialContainer(container: Record<string, unknown>): boolean {
  if (container.parser_error === true || container.truncated === true) return true;
  const status = container.parse_status;
  if (typeof status === "string" && PARTIAL_STATUS_TOKENS.some((t) => status.toLowerCase().includes(t)))
    return true;
  const decrypt = container.decrypt_status;
  if (typeof decrypt === "string" && !DECRYPT_OK.has(decrypt.toLowerCase())) return true;
  const coverage = container.coverage;
  if (coverage === "partial" || (isRecord(coverage) && coverage.status === "partial")) return true;
  return Object.entries(container).some(([key, value]) => key.endsWith("_truncated") && value === true);
}

/** 부분 결과: the row (or its `details`) says a parser could not read it completely. */
export function rowIsPartial(row: GridRow): boolean {
  const details = isRecord(row.fields.details) ? row.fields.details : {};
  const type = String(details.artifact_type ?? row.artifactType ?? "").toLowerCase();
  if (PARTIAL_TYPE_TOKENS.some((token) => type.includes(token))) return true;
  return partialContainer(row.fields) || partialContainer(details);
}

// --- predicates & params -------------------------------------------------------------------

export interface RowConditionFilters extends ClockConditions {
  partial?: boolean;
  content?: readonly string[];
  geo?: string;
}

export function parseGeo(value: string | undefined): [number, number, number, number] | null {
  if (!value) return null;
  const parts = value.split(",").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n))) return null;
  return parts as [number, number, number, number];
}

/** Client check of the clock / 부분 결과 / 콘텐츠 유형 / 위치 conditions (the time range is checked by the caller). */
export function rowMatchesConditions(row: GridRow, filters: RowConditionFilters, tz: string): boolean {
  if (hasClock(filters)) {
    const at = parseInstant(row.timestamp);
    if (!at || !clockMatches(at, filters, tz)) return false;
  }
  if (filters.partial && !rowIsPartial(row)) return false;
  if (filters.content?.length) {
    const types = rowContentTypes(row);
    if (!filters.content.some((id) => types.has(id as never))) return false;
  }
  const box = parseGeo(filters.geo);
  if (box) {
    const point = rowCoordinates(row);
    if (!point) return false;
    const [lat0, lon0, lat1, lon1] = box;
    if (point.lat < lat0 || point.lat > lat1 || point.lon < lon0 || point.lon > lon1) return false;
  }
  return true;
}

/** An ISO instant for the server from a filter bound (`YYYY-MM-DDTHH:mm` = browser local, like the inputs). */
export function serverInstant(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : new Date(ms).toISOString();
}

export type ServerConditionParams = Record<string, string | string[]>;

/**
 * Query parameters of the row conditions a listing applies server-side. `geo` only where the
 * listing supports it (`/artifacts`); `tz` only with a clock condition.
 */
export function serverConditionParams(
  filters: RowConditionFilters & { from?: string; to?: string },
  tz: string,
  options: { time: boolean; geo: boolean },
): ServerConditionParams {
  const params: ServerConditionParams = {};
  if (options.time) {
    const from = serverInstant(filters.from);
    const to = serverInstant(filters.to);
    if (from) params.from = from;
    if (to) params.to = to;
  }
  if (hasClock(filters)) {
    params.tz = zoneName(tz);
    if (filters.weekdays?.length) params.weekday = [...filters.weekdays];
    const window = parseHours(filters.hours);
    if (window) params.hours = `${String(window[0]).padStart(2, "0")}-${String(window[1]).padStart(2, "0")}`;
    if (filters.offhours) params.offhours = "1";
  }
  if (filters.partial) params.partial = "1";
  if (filters.content?.length) params.content = [...filters.content];
  if (options.geo && parseGeo(filters.geo)) params.geo = filters.geo as string;
  return params;
}

/** `&k=v…` of server condition params (repeated keys for lists). */
export function conditionQueryString(params: ServerConditionParams | undefined): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    for (const item of Array.isArray(value) ? value : [value]) search.append(key, item);
  }
  const text = search.toString();
  return text ? `&${text}` : "";
}

export function isWeekdayId(value: string): boolean {
  return WEEKDAY_IDS.includes(value);
}

// --- relative ranges --------------------------------------------------------------------------

/** Local `YYYY-MM-DDTHH:mm` of a Date (datetime-local value). */
function localInput(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** 사건 시각 ± n시간 (an incident window, or a single incident time). */
export function incidentRange(
  start: string,
  hours: number,
  end?: string,
): { from: string; to: string } | null {
  // `YYYY-MM-DDTHH:mm` (datetime-local) is browser-local time like the range inputs; ISO with a zone as given.
  const a = Date.parse(start);
  if (Number.isNaN(a)) return null;
  const parsedEnd = end ? Date.parse(end) : Number.NaN;
  const b = Number.isNaN(parsedEnd) ? a : parsedEnd;
  const lo = Math.min(a, b) - hours * 3_600_000;
  const hi = Math.max(a, b) + hours * 3_600_000;
  return { from: localInput(new Date(lo)), to: localInput(new Date(hi)) };
}

export interface Incident {
  start: Date;
  /** ISO end of an incident window, when the analysis set one. */
  end: string | null;
}

/** The run's incident time: the newest completed 특이사항 (`triage-flags`) analysis' `incident_start`/`incident_end`. */
export function incidentFromAnalyses(
  analyses: ReadonlyArray<{
    kind: string;
    status: string;
    options: Record<string, unknown>;
    created_at: string;
  }>,
): Incident | null {
  const done = analyses
    .filter((job) => job.kind === "triage-flags" && job.status === "completed")
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
  for (const job of done) {
    const start =
      typeof job.options.incident_start === "string" ? parseInstant(job.options.incident_start) : null;
    if (!start) continue;
    const rawEnd = job.options.incident_end;
    const end = typeof rawEnd === "string" && parseInstant(rawEnd) ? rawEnd : null;
    return { start, end };
  }
  return null;
}
