/**
 * 조건 기억 (viewer-families U-F8, AXIOM 필터 바): the three most recent time ranges and saved
 * condition sets, per browser profile. Storage may be unavailable (private mode): every access is
 * wrapped and the UI simply shows nothing to recall.
 */

import { normalizeContent, normalizeHours, normalizeWeekdays, parseGeo } from "./conditionValues";
import { EMPTY_FILTERS, type FilterState, filtersEqual } from "./filterModel";

export const RECENT_RANGES_KEY = "rapidtriage.v2.conditions.recentRanges";
export const SAVED_CONDITIONS_KEY = "rapidtriage.v2.conditions.saved";
export const RECENT_RANGES_MAX = 3;
export const SAVED_CONDITIONS_MAX = 10;

export interface TimeRange {
  from?: string;
  to?: string;
}

export interface SavedCondition {
  name: string;
  filters: FilterState;
  savedAt: string;
}

function read<T>(key: string, guard: (value: unknown) => value is T): T | null {
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    return guard(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function write(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Not remembered; nothing else depends on it.
  }
}

function isRangeList(value: unknown): value is TimeRange[] {
  return (
    Array.isArray(value) &&
    value.every(
      (r) =>
        r &&
        typeof r === "object" &&
        (r.from === undefined || typeof r.from === "string") &&
        (r.to === undefined || typeof r.to === "string"),
    )
  );
}

function isRecordValue(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringList<T extends string = string>(value: unknown): T[] {
  return Array.isArray(value) ? (value.filter((v) => typeof v === "string" && v !== "") as T[]) : [];
}

const STATUSES: ReadonlySet<string> = new Set(["relevant", "needs-review", "excluded", "include-in-report"]);

/**
 * A stored condition set rebuilt field by field on top of EMPTY_FILTERS: a hand-edited or older
 * entry can never hand the panel a non-array (`.includes` on undefined) or an unknown status.
 */
export function normalizeFilters(raw: unknown): FilterState {
  const src = isRecordValue(raw) ? raw : {};
  const text = (value: unknown) => (typeof value === "string" && value ? value : undefined);
  const columns = (Array.isArray(src.columns) ? src.columns : []).filter(
    (c): c is FilterState["columns"][number] =>
      isRecordValue(c) &&
      typeof c.col === "string" &&
      typeof c.op === "string" &&
      typeof c.value === "string",
  );
  const grade =
    src.flagGrade === "A" || src.flagGrade === "B" || src.flagGrade === "C" ? src.flagGrade : undefined;
  const flags = stringList(src.flags);
  const weekdays = normalizeWeekdays(stringList(src.weekdays));
  const hours = normalizeHours(src.hours);
  const content = normalizeContent(stringList(src.content));
  const geo = text(src.geo);
  return {
    ...EMPTY_FILTERS,
    ...(text(src.from) ? { from: text(src.from) } : {}),
    ...(text(src.to) ? { to: text(src.to) } : {}),
    statuses: stringList<FilterState["statuses"][number]>(src.statuses).filter((s) => STATUSES.has(s)),
    types: stringList(src.types),
    tags: stringList(src.tags),
    ext: stringList(src.ext),
    path: text(src.path) ?? "",
    ...(src.notes === true ? { notes: true } : {}),
    columns,
    ...(flags.length ? { flags } : {}),
    ...(grade ? { flagGrade: grade } : {}),
    // Row conditions (r4 §2.3): saved condition sets carry them too.
    // Unknown weekday / content ids, empty hour windows and out-of-range boxes are dropped.
    ...(weekdays.length ? { weekdays } : {}),
    ...(hours ? { hours } : {}),
    ...(src.offhours === true ? { offhours: true } : {}),
    ...(src.partial === true ? { partial: true } : {}),
    ...(content.length ? { content } : {}),
    ...(geo && parseGeo(geo) ? { geo } : {}),
  };
}

function savedList(value: unknown): SavedCondition[] {
  if (!Array.isArray(value)) return [];
  const out: SavedCondition[] = [];
  const names = new Set<string>();
  for (const entry of value) {
    if (!isRecordValue(entry) || typeof entry.name !== "string" || !entry.name || names.has(entry.name))
      continue;
    names.add(entry.name);
    out.push({
      name: entry.name,
      filters: normalizeFilters(entry.filters),
      savedAt: typeof entry.savedAt === "string" ? entry.savedAt : "",
    });
  }
  return out;
}

export function recentRanges(): TimeRange[] {
  return (read(RECENT_RANGES_KEY, isRangeList) ?? []).slice(0, RECENT_RANGES_MAX);
}

/** Remember an applied range (most recent first, no duplicates, at most three). */
export function rememberRange(range: TimeRange): TimeRange[] {
  if (!range.from && !range.to) return recentRanges();
  const next = [
    { ...(range.from ? { from: range.from } : {}), ...(range.to ? { to: range.to } : {}) },
    ...recentRanges().filter((r) => r.from !== range.from || r.to !== range.to),
  ].slice(0, RECENT_RANGES_MAX);
  write(RECENT_RANGES_KEY, next);
  return next;
}

export function savedConditions(): SavedCondition[] {
  try {
    const raw = window.localStorage.getItem(SAVED_CONDITIONS_KEY);
    return raw ? savedList(JSON.parse(raw)) : [];
  } catch {
    return [];
  }
}

/**
 * Save a condition set. The same conditions replace their older entry; another set with the same
 * name gets " (2)", " (3)" … so names (the list keys, the delete target) stay unique.
 */
export function saveCondition(name: string, filters: FilterState): SavedCondition[] {
  const rest = savedConditions().filter((s) => !filtersEqual(s.filters, filters));
  const taken = new Set(rest.map((s) => s.name));
  let unique = name;
  for (let n = 2; taken.has(unique); n++) unique = `${name} (${n})`;
  const entry: SavedCondition = {
    name: unique,
    filters: normalizeFilters(filters),
    savedAt: new Date().toISOString(),
  };
  const next = [entry, ...rest].slice(0, SAVED_CONDITIONS_MAX);
  write(SAVED_CONDITIONS_KEY, next);
  return next;
}

export function removeSavedCondition(name: string): SavedCondition[] {
  const next = savedConditions().filter((s) => s.name !== name);
  write(SAVED_CONDITIONS_KEY, next);
  return next;
}
