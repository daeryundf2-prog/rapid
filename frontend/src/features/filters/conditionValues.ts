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

// --- relative date presets (R7 L1, C-D5) ---------------------------------------------------------
// "최근 7일" counted back from the wall clock finds nothing in 2025 evidence opened in 2026: the
// presets count back from the newest evidence time (`timeline_max_ts` of the run detail), else
// from the run's start, and say which ("증거 기준 최근 7일").

export type RelativePreset = "today" | "1d" | "7d" | "30d";

export const RELATIVE_PRESETS: readonly RelativePreset[] = ["today", "1d", "7d", "30d"];

const RELATIVE_DAYS: Record<Exclude<RelativePreset, "today">, number> = { "1d": 1, "7d": 7, "30d": 30 };

/** What the presets count back from: the newest evidence time, the run start, or the clock. */
export interface PresetAnchor {
  /** Epoch ms of the anchor. */
  ms: number;
  source: "evidence" | "run-start" | "now";
}

/** The anchor of a run: `timeline_max_ts` (evidence), else its start, else now. */
export function presetAnchor(
  evidenceMax: string | null | undefined,
  runStart: string | null | undefined,
  now: number = Date.now(),
): PresetAnchor {
  const evidence = evidenceMax ? Date.parse(evidenceMax) : Number.NaN;
  if (Number.isFinite(evidence)) return { ms: evidence, source: "evidence" };
  const start = runStart ? Date.parse(runStart) : Number.NaN;
  if (Number.isFinite(start)) return { ms: start, source: "run-start" };
  return { ms: now, source: "now" };
}

const ANCHOR_PREFIX: Record<PresetAnchor["source"], string> = {
  evidence: "증거 기준 ",
  "run-start": "런 시작 기준 ",
  now: "",
};

/** "증거 기준 최근 7일" · "증거 기준 마지막 날" (today) · "최근 7일" (clock). */
export function relativePresetLabel(preset: RelativePreset, anchor: PresetAnchor): string {
  const prefix = ANCHOR_PREFIX[anchor.source];
  if (preset === "today") return anchor.source === "now" ? "오늘" : `${prefix}마지막 날`;
  return `${prefix}최근 ${RELATIVE_DAYS[preset]}일`;
}

/**
 * R-6: the segment's own short label ("최근 7일" · "마지막 날" · "오늘"); the anchor prefix is
 * shown once above the segment (relativePresetCaption) so the buttons fit the popover.
 */
export function relativePresetShortLabel(preset: RelativePreset, anchor: PresetAnchor): string {
  if (preset === "today") return anchor.source === "now" ? "오늘" : "마지막 날";
  return `최근 ${RELATIVE_DAYS[preset]}일`;
}

/** "증거 기준" · "런 시작 기준" — the caption over the preset segment; "" when counted from now. */
export function relativePresetCaption(anchor: PresetAnchor): string {
  return ANCHOR_PREFIX[anchor.source].trim();
}

/** Browser-local `YYYY-MM-DDTHH:mm` (the value format of the filter's datetime-local inputs). */
function localInput(ms: number): string {
  const date = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/**
 * The range of a preset counted back from the anchor: N days before it up to its minute (the
 * `to` bound covers the whole minute), "today" = the anchor's local day up to the anchor.
 */
export function relativePresetRange(
  preset: RelativePreset,
  anchor: PresetAnchor,
): { from: string; to: string } {
  let start: number;
  if (preset === "today") {
    const day = new Date(anchor.ms);
    day.setHours(0, 0, 0, 0);
    start = day.getTime();
  } else {
    start = anchor.ms - RELATIVE_DAYS[preset] * 86_400_000;
  }
  return { from: localInput(start), to: localInput(anchor.ms) };
}

/** The preset the current range equals (a minute of slack), or null. */
export function activeRelativePreset(
  range: { from?: string; to?: string },
  anchor: PresetAnchor,
): RelativePreset | null {
  if (!range.from || !range.to) return null;
  for (const preset of RELATIVE_PRESETS) {
    const want = relativePresetRange(preset, anchor);
    if (
      Math.abs(Date.parse(want.from) - Date.parse(range.from)) <= 60_000 &&
      Math.abs(Date.parse(want.to) - Date.parse(range.to)) <= 60_000
    )
      return preset;
  }
  return null;
}

// --- 계열 · 중복 · 예외 항목 (R7 갈래 A) ----------------------------------------------------------
// Keep aligned with `rapidtriage/api/app/row_conditions.py` (parse_row_sets) and
// `rapidtriage/core/irregular.py` (CATEGORIES, CATEGORY_LABELS).

/** `dup=`: 원본만 · 중복만 · 중복 있는 항목 (the original or a duplicate of a group with duplicates). */
export const DUP_STATUSES = ["original", "duplicate", "any"] as const;
export type DupStatus = (typeof DUP_STATUSES)[number];

export const DUP_LABELS: Readonly<Record<DupStatus, string>> = {
  original: "원본만",
  duplicate: "중복만",
  any: "중복 있는 항목",
};

/** `dup_mode=`: how items are compared (absent = 항목별). */
export const DUP_MODES = ["item", "family", "custodian"] as const;
export type DupMode = (typeof DUP_MODES)[number];

export const DUP_MODE_LABELS: Readonly<Record<DupMode, string>> = {
  item: "항목별",
  family: "계열별",
  custodian: "보관자 순위별",
};

/** `irregular=` category ids, in the server's order. */
export const IRREGULAR_IDS = [
  "bad-extension",
  "corrupted",
  "deleted",
  "empty",
  "encrypted",
  "non-searchable-pdf",
  "text-stripped",
  "unrecognized",
  "unsupported",
] as const;
export type IrregularId = (typeof IRREGULAR_IDS)[number];

export const IRREGULAR_LABELS: Readonly<Record<IrregularId, string>> = {
  "bad-extension": "확장자 불일치",
  corrupted: "손상·부분 읽기",
  deleted: "삭제됨",
  empty: "빈 파일",
  encrypted: "암호화",
  "non-searchable-pdf": "검색 불가 PDF",
  "text-stripped": "본문 제외(바이너리)",
  unrecognized: "형식 미상",
  unsupported: "미지원 형식",
};

export function isDupStatus(value: unknown): value is DupStatus {
  return typeof value === "string" && (DUP_STATUSES as readonly string[]).includes(value);
}

export function isDupMode(value: unknown): value is DupMode {
  return typeof value === "string" && (DUP_MODES as readonly string[]).includes(value);
}

/** Known category ids of a list, in server order (unknown ids dropped). */
export function normalizeIrregular(values: readonly unknown[]): IrregularId[] {
  return IRREGULAR_IDS.filter((id) => values.includes(id));
}

/** Korean name of a category id (the id itself never reaches the screen: unknown → "기타 예외"). */
export function irregularLabel(id: string): string {
  return (IRREGULAR_LABELS as Record<string, string>)[id] ?? "기타 예외";
}

const ITEM_REF =
  /^(artifacts:[A-Za-z0-9._-]{1,128}:\/artifacts\/\d+(#(entry|attachment):\d+)?|files::\/(candidates|inventory)\/\d+|analysis:[A-Za-z0-9._-]{1,128}:\/rows\/\d+)$/;

/** A `family=` item ref the server accepts (`artifacts:<kind>:/artifacts/<n>`, `files::/candidates/<n>`, …). */
export function isFamilyRef(value: unknown): value is string {
  return typeof value === "string" && value.length <= 2048 && ITEM_REF.test(value);
}

/** Valid, de-duplicated `family=` refs of a list (at most 500, like the server). */
export function normalizeFamilyRefs(values: readonly unknown[]): string[] {
  return [...new Set(values.filter(isFamilyRef))].slice(0, 500);
}
