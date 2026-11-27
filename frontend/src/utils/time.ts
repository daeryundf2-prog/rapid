/** Display timezone: "utc", "local" (browser) or an IANA name such as "Asia/Seoul". */
export type TimezoneChoice = string;

export interface FormatOptions {
  /** "date" · "minute" · "second" (default) · "ms". */
  precision?: "date" | "minute" | "second" | "ms";
}

export function isValidTimezone(tz: string): boolean {
  if (tz === "utc" || tz === "local") return true;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/** Parse ISO text (naive text counts as UTC), epoch seconds or a Date; null when invalid. */
export function parseInstant(value: string | number | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === "") return null;
  let date: Date;
  if (value instanceof Date) date = value;
  else if (typeof value === "number") date = new Date(value * 1000);
  else {
    const text = value.trim();
    const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(text);
    const naive = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(text) && !hasZone;
    // 7-digit FILETIME fractions ("…56.1234567Z"): Date keeps milliseconds only.
    const ms = text.replace(/(\.\d{3})\d+/, "$1");
    date = new Date(naive ? `${ms.replace(" ", "T")}Z` : ms);
  }
  return Number.isNaN(date.getTime()) ? null : date;
}

function zoneOf(tz: string): string | undefined {
  if (tz === "utc") return "UTC";
  if (tz === "local") return undefined;
  return isValidTimezone(tz) ? tz : "UTC";
}

function wallClock(date: Date, tz: string): Record<string, number> {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: zoneOf(tz),
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(date);
  const out: Record<string, number> = {};
  for (const p of parts) if (p.type !== "literal") out[p.type] = Number(p.value);
  return out;
}

/** Offset of `tz` at `date` in minutes east of UTC. */
export function tzOffsetMinutes(tz: string, date: Date = new Date()): number {
  const w = wallClock(date, tz);
  const asUtc = Date.UTC(
    w.year ?? 1970,
    (w.month ?? 1) - 1,
    w.day ?? 1,
    w.hour ?? 0,
    w.minute ?? 0,
    w.second ?? 0,
  );
  return Math.round((asUtc - Math.floor(date.getTime() / 1000) * 1000) / 60000);
}

/** "UTC+09:00" / "UTC+00:00" label for the status bar. */
export function tzOffsetLabel(tz: string, date: Date = new Date()): string {
  const minutes = tzOffsetMinutes(tz, date);
  const sign = minutes < 0 ? "-" : "+";
  const abs = Math.abs(minutes);
  return `UTC${sign}${String(Math.floor(abs / 60)).padStart(2, "0")}:${String(abs % 60).padStart(2, "0")}`;
}

/** `YYYY-MM-DD HH:mm:ss` in the chosen timezone; unparseable input is returned unchanged, empty → "—". */
export function formatTimestamp(
  value: string | number | Date | null | undefined,
  tz: TimezoneChoice,
  options: FormatOptions = {},
): string {
  const date = parseInstant(value);
  if (!date) return value === null || value === undefined || value === "" ? "—" : String(value);
  const w = wallClock(date, tz);
  const p2 = (n: number | undefined) => String(n ?? 0).padStart(2, "0");
  const day = `${String(w.year).padStart(4, "0")}-${p2(w.month)}-${p2(w.day)}`;
  const precision = options.precision ?? "second";
  if (precision === "date") return day;
  const minute = `${day} ${p2(w.hour)}:${p2(w.minute)}`;
  if (precision === "minute") return minute;
  const second = `${minute}:${p2(w.second)}`;
  if (precision === "second") return second;
  return `${second}.${String(((date.getTime() % 1000) + 1000) % 1000).padStart(3, "0")}`;
}

/** ISO instant shifted by `ms` (for ±1 h timeline windows); null when the input is unparseable. */
export function shiftIso(value: string | number | Date | null | undefined, ms: number): string | null {
  const date = parseInstant(value);
  return date ? new Date(date.getTime() + ms).toISOString() : null;
}

// ---------------------------------------------------------------------------
// Evidence timestamps (viewer redesign §2): one formatter for the record view, the provenance
// block and the grid — local wall clock in the display zone with the zone named, sub-second
// digits kept as the source wrote them, the UTC reading beside it, FILETIME in the tooltip.
// ---------------------------------------------------------------------------

/** Zone abbreviations by IANA name: [standard, daylight] (offset decides which). */
const ZONE_ABBR: Record<string, [string, string?]> = {
  UTC: ["UTC"],
  "Etc/UTC": ["UTC"],
  "Asia/Seoul": ["KST"],
  "Asia/Tokyo": ["JST"],
  "Asia/Shanghai": ["CST"],
  "Asia/Hong_Kong": ["HKT"],
  "Asia/Singapore": ["SGT"],
  "Europe/London": ["GMT", "BST"],
  "Europe/Berlin": ["CET", "CEST"],
  "Europe/Paris": ["CET", "CEST"],
  "America/New_York": ["EST", "EDT"],
  "America/Chicago": ["CST", "CDT"],
  "America/Denver": ["MST", "MDT"],
  "America/Los_Angeles": ["PST", "PDT"],
  "Australia/Sydney": ["AEST", "AEDT"],
};

/** IANA name of a display-zone choice ("utc" → UTC, "local" → the browser's zone). */
export function zoneName(tz: TimezoneChoice): string {
  if (tz === "utc") return "UTC";
  if (tz === "local") {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
    } catch {
      return "UTC";
    }
  }
  return isValidTimezone(tz) ? tz : "UTC";
}

function offsetText(minutes: number): string {
  const sign = minutes < 0 ? "-" : "+";
  const abs = Math.abs(minutes);
  return `${sign}${String(Math.floor(abs / 60)).padStart(2, "0")}:${String(abs % 60).padStart(2, "0")}`;
}

/** "KST+09:00" · "UTC" · "UTC+05:30" (no known abbreviation) for `tz` at `date`. */
export function zoneLabel(tz: TimezoneChoice, date: Date = new Date()): string {
  const name = zoneName(tz);
  const minutes = tzOffsetMinutes(tz === "local" ? "local" : name, date);
  const abbr = ZONE_ABBR[name];
  if (name === "UTC" || name === "Etc/UTC") return "UTC";
  if (!abbr) return `UTC${offsetText(minutes)}`;
  // Daylight only when the instant's offset is past the zone's standard offset, read from the
  // runtime's IANA zone data as the smaller of that year's January and July offsets: January is
  // summer (daylight) in the southern hemisphere, so January alone is not the standard offset.
  const year = date.getUTCFullYear();
  const standard = Math.min(
    tzOffsetMinutes(name, new Date(Date.UTC(year, 0, 15))),
    tzOffsetMinutes(name, new Date(Date.UTC(year, 6, 15))),
  );
  const label = abbr[1] && minutes > standard ? abbr[1] : abbr[0];
  return `${label}${offsetText(minutes)}`;
}

/** Fraction-of-second digits as the source wrote them ("427", "1234567"); trailing zeros dropped. */
export function fractionDigits(value: string | number | Date | null | undefined): string {
  if (value instanceof Date) return trimFraction(String(value.getUTCMilliseconds()).padStart(3, "0"));
  if (typeof value === "number") {
    const ms = Math.round((value % 1) * 1000);
    return trimFraction(String(ms).padStart(3, "0"));
  }
  if (typeof value !== "string") return "";
  const match = /\d{2}:\d{2}:\d{2}[.,](\d+)/.exec(value);
  return match?.[1] ? trimFraction(match[1].slice(0, 9)) : "";
}

function trimFraction(digits: string): string {
  const trimmed = digits.replace(/0+$/, "");
  if (!trimmed) return "";
  // Whole groups of three (ms · µs) unless the source carried 100 ns ticks (7 digits).
  if (trimmed.length <= 3) return digits.slice(0, 3).padEnd(3, "0");
  if (trimmed.length <= 6) return digits.slice(0, 6).padEnd(6, "0");
  return trimmed.slice(0, 7);
}

/** FILETIME (100 ns ticks since 1601-01-01 UTC) of an instant, sub-ms digits from the source text. */
export function filetimeOf(value: string | number | Date | null | undefined): string | null {
  const date = parseInstant(value);
  if (!date) return null;
  const fraction = fractionDigits(value).padEnd(7, "0").slice(0, 7);
  const seconds = BigInt(Math.floor(date.getTime() / 1000)) + 11_644_473_600n;
  return (seconds * 10_000_000n + BigInt(fraction || "0")).toString();
}

export interface EvidenceTime {
  /** Wall clock in the display zone: "2025-05-29 23:25:26.427". */
  local: string;
  /** The display zone: "KST+09:00" / "UTC". */
  zone: string;
  /** "UTC 14:25:26.427" (date added when it differs); null when the display zone is UTC. */
  utc: string | null;
  /** One line: "2025-05-29 23:25:26.427 (KST+09:00) · UTC 14:25:26.427". */
  text: string;
  /** Canonical UTC ISO of the instant (ms precision). */
  iso: string;
  /** The value as the record wrote it. */
  raw: string;
}

/** The evidence reading of a timestamp, or null when it does not parse. */
export function evidenceTime(
  value: string | number | Date | null | undefined,
  tz: TimezoneChoice,
): EvidenceTime | null {
  const date = parseInstant(value);
  if (!date) return null;
  const fraction = fractionDigits(value);
  const tail = fraction ? `.${fraction}` : "";
  const local = `${formatTimestamp(date, tz)}${tail}`;
  const zone = zoneLabel(tz, date);
  let utc: string | null = null;
  if (zone !== "UTC") {
    const utcFull = formatTimestamp(date, "utc");
    const sameDay = utcFull.slice(0, 10) === local.slice(0, 10);
    utc = `UTC ${sameDay ? utcFull.slice(11) : utcFull}${tail}`;
  }
  return {
    local,
    zone,
    utc,
    text: `${local} (${zone})${utc ? ` · ${utc}` : ""}`,
    iso: date.toISOString(),
    raw: value instanceof Date ? value.toISOString() : String(value),
  };
}

/** The one-line evidence reading; unparseable input is returned unchanged, empty → "—". */
export function formatEvidenceTime(
  value: string | number | Date | null | undefined,
  tz: TimezoneChoice,
): string {
  const reading = evidenceTime(value, tz);
  if (reading) return reading.text;
  return value === null || value === undefined || value === "" ? "—" : String(value);
}

// ---------------------------------------------------------------------------
// Lossless evidence times (D14 #8, #11): one reading shared by the grid cell, its tooltip and the
// selection CSV. A wall clock whose zone the evidence does not establish ("local-unknown") is
// shown as written and never converted into the display zone; an instant keeps every fraction
// digit the source wrote (100 ns ticks) in its exact UTC text, and an unsafe FILETIME number
// (an 18-digit JSON number already rounded by the double parse) is never shown as the original.
// ---------------------------------------------------------------------------

/** Source zone labels of a wall clock with an undetermined zone (rapidtriage LOCAL_TIMEZONE_LABELS). */
export const WALL_CLOCK_ZONES: Readonly<Record<string, true>> = {
  "local-unknown": true,
  "exif-local": true,
  local: true,
  "device-local": true,
};

const WALL_CLOCK_RE = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,](\d+))?$/;

export type ZoneStatus = "utc-instant" | "wall-clock-zone-undetermined";

export interface ExactEvidenceTime {
  /** Display text with every source fraction digit; a wall clock is shown as written. */
  display: string;
  /** Exact UTC text with the source fraction digits ("2024-01-01T00:00:00.0000007Z"); null for a wall clock. */
  exactUtc: string | null;
  /** The wall clock as written ("2024-01-02 09:00:00"); null for an instant. */
  wallClock: string | null;
  zoneStatus: ZoneStatus;
  /** FILETIME ticks as a decimal string: the source value when exact, else derived from the text. */
  filetime: string | null;
  filetimeBasis: "source" | "derived" | null;
}

/** A source FILETIME the browser still holds exactly: decimal text, or a safe integer number. */
function exactSourceFiletime(raw: string | number | null | undefined): string | null {
  if (typeof raw === "string") return /^\d+$/.test(raw.trim()) ? raw.trim() : null;
  if (typeof raw === "number") return Number.isSafeInteger(raw) && raw > 0 ? String(raw) : null;
  return null;
}

/** The wall clock of naive text labelled with an undetermined zone, else null. */
function wallClockOf(value: unknown, sourceZone: string | null | undefined): string | null {
  if (typeof value !== "string" || !sourceZone || !Object.hasOwn(WALL_CLOCK_ZONES, sourceZone)) return null;
  const match = WALL_CLOCK_RE.exec(value.trim());
  if (!match) return null;
  return `${match[1]} ${match[2]}${match[3] ? `.${match[3]}` : ""}`;
}

/** The lossless reading of an evidence time, or null when it does not parse. */
export function exactEvidenceTime(
  value: string | number | Date | null | undefined,
  tz: TimezoneChoice,
  options: { sourceZone?: string | null; rawFiletime?: string | number | null } = {},
): ExactEvidenceTime | null {
  const wallClock = wallClockOf(value, options.sourceZone);
  if (wallClock) {
    return {
      display: `${wallClock} (현지 시각·시간대 미확정)`,
      exactUtc: null,
      wallClock,
      zoneStatus: "wall-clock-zone-undetermined",
      filetime: null,
      filetimeBasis: null,
    };
  }
  const reading = evidenceTime(value, tz);
  const date = parseInstant(value);
  if (!reading || !date) return null;
  const sourceFraction =
    typeof value === "string" ? (/\d{2}:\d{2}:\d{2}[.,](\d+)/.exec(value)?.[1] ?? "") : "";
  const fraction = sourceFraction ? sourceFraction.slice(0, 7) : fractionDigits(value);
  const exactUtc = `${date.toISOString().slice(0, 19)}${fraction ? `.${fraction}` : ""}Z`;
  const source = exactSourceFiletime(options.rawFiletime);
  const derived = filetimeOf(value);
  return {
    display: reading.text,
    exactUtc,
    wallClock: null,
    zoneStatus: "utc-instant",
    filetime: source ?? derived,
    filetimeBasis: source ? "source" : derived ? "derived" : null,
  };
}

/** Korean label of a zone status (CSV "시간대 상태" column, tooltip). */
export function zoneStatusLabel(status: ZoneStatus): string {
  return status === "utc-instant" ? "UTC 기준 시각" : "현지 시각(시간대 미확정·환산 안 함)";
}

// ---------------------------------------------------------------------------
// Integer 100 ns ticks (D16 #12, #13): order and same-instant checks never go through a Date
// (milliseconds) or a string compare (".000001" vs ".0000007" sort wrongly as text).
// ---------------------------------------------------------------------------

const TICK_TEXT_RE =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$/i;

/** UTC FILETIME ticks of ISO text and whether the text named its zone. */
export interface UtcTicks {
  ticks: bigint;
  offset: boolean;
}

/**
 * UTC FILETIME ticks (100 ns since 1601-01-01) of ISO text, every fraction digit up to seven
 * kept (naive text is read as UTC, `offset: false`). Null when the text is no ISO date-time.
 * Mirrors rapidtriage.core.filetime.event_timestamp_utc_ticks.
 */
export function utcTicksOf(value: unknown): UtcTicks | null {
  if (typeof value !== "string") return null;
  const match = TICK_TEXT_RE.exec(value.trim());
  if (!match) return null;
  const [, y, mo, d, h, mi, s, fraction = "", zone = ""] = match;
  const date = new Date(0);
  date.setUTCFullYear(Number(y), Number(mo) - 1, Number(d));
  date.setUTCHours(Number(h), Number(mi), Number(s), 0);
  if (Number.isNaN(date.getTime())) return null;
  let seconds = BigInt(Math.floor(date.getTime() / 1000)) + 11_644_473_600n;
  if (zone && zone.toUpperCase() !== "Z") {
    const digits = zone.slice(1).replace(":", "");
    const minutes = Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2));
    seconds -= BigInt((zone.startsWith("-") ? -1 : 1) * minutes * 60);
  }
  return {
    ticks: seconds * 10_000_000n + BigInt(fraction.slice(0, 7).padEnd(7, "0")),
    offset: zone !== "",
  };
}

/**
 * `fields[key + "_100ns"]` when that sibling is the 7-digit text of the same instant as `value`
 * (EVTX `timestamp_100ns`, LNK `target_*_at_100ns`, DestList `*last_modified_at_100ns`), else
 * `value` — the server's sort rule (rapidtriage.core.filetime.precise_time_value).
 */
export function preciseTimeOf(fields: Record<string, unknown>, key: string, value: string): string {
  const precise = fields[`${key}_100ns`];
  if (typeof precise !== "string" || !precise.trim()) return value;
  const a = utcTicksOf(precise);
  const b = utcTicksOf(value);
  if (!a || !b?.offset) return value;
  return a.ticks / 10n === b.ticks / 10n ? precise : value;
}

/**
 * Sort key of an evidence time. Group 0: UTC instants by exact ticks (the source's decimal ticks
 * when they agree with the text, else the text's); group 1: wall clocks of undetermined zone, a
 * group of their own never placed among UTC instants; group 2: unparseable text.
 */
export interface EvidenceSortKey {
  group: 0 | 1 | 2;
  ticks: bigint;
  text: string;
}

export function evidenceSortKey(
  value: string | null | undefined,
  sourceZone: string | null | undefined,
  sourceTicks: string | number | null | undefined,
): EvidenceSortKey {
  const text = value ?? "";
  const reading = utcTicksOf(text);
  if (sourceZone && Object.hasOwn(WALL_CLOCK_ZONES, sourceZone) && reading && !reading.offset) {
    return { group: 1, ticks: reading.ticks, text };
  }
  const exact = exactSourceFiletime(sourceTicks ?? null);
  if (exact && reading && BigInt(exact) / 10n === reading.ticks / 10n) {
    return { group: 0, ticks: BigInt(exact), text };
  }
  return reading ? { group: 0, ticks: reading.ticks, text } : { group: 2, ticks: 0n, text };
}

/** Ascending comparison of two evidence sort keys. */
export function compareEvidenceSortKeys(a: EvidenceSortKey, b: EvidenceSortKey): number {
  if (a.group !== b.group) return a.group - b.group;
  if (a.ticks !== b.ticks) return a.ticks < b.ticks ? -1 : 1;
  return a.text < b.text ? -1 : a.text > b.text ? 1 : 0;
}

/**
 * The UTC instants a wall clock can be under an assumed zone (the evidence's own zone setting), or
 * null when no valid zone is given. Each candidate round-trips: read back in the zone it is the
 * same wall clock. One candidate on an ordinary day, none in a daylight-saving gap (the wall clock
 * never existed there) and two in a repeated hour (both kept, the earlier first). Kept apart from
 * the source value: the assumption is the analyst's.
 */
export function assumedUtcCandidates(
  wallClock: string,
  assumedZone: string | null | undefined,
): string[] | null {
  if (!assumedZone || assumedZone === "local" || !isValidTimezone(assumedZone)) return null;
  const match = WALL_CLOCK_RE.exec(wallClock.trim());
  if (!match) return null;
  const asUtc = new Date(`${match[1]}T${match[2]}Z`);
  if (Number.isNaN(asUtc.getTime())) return null;
  const zone = zoneName(assumedZone);
  const day = 86_400_000;
  // The offsets in force a day before, at and a day after the wall clock read as UTC: every offset
  // the wall clock can carry (zones change offset at most once within a day).
  const offsets = new Set(
    [-day, 0, day].map((shift) => tzOffsetMinutes(zone, new Date(asUtc.getTime() + shift))),
  );
  const fraction = match[3] ? `.${match[3].slice(0, 7)}` : "";
  return [...offsets]
    .map((offset) => ({ offset, utc: new Date(asUtc.getTime() - offset * 60_000) }))
    .filter(({ offset, utc }) => tzOffsetMinutes(zone, utc) === offset)
    .sort((a, b) => a.utc.getTime() - b.utc.getTime())
    .map(({ utc }) => `${utc.toISOString().slice(0, 19)}${fraction}Z`);
}

/** Short name of the display zone at `date`: "KST" · "UTC" · "UTC+05:30" (no known abbreviation). */
export function zoneShort(tz: TimezoneChoice, date: Date): string {
  const zone = zoneLabel(tz, date);
  return zone.startsWith("UTC") ? zone : zone.replace(/[+-]\d{2}:\d{2}$/, "") || zone;
}

/** Grid cells: "2025-05-29 23:25:26 KST" — seconds, the zone named (the tooltip has the rest).
 * A wall clock of undetermined zone is shown as written, marked, never shifted into `tz`. */
export function formatGridTime(
  value: string | number | Date | null | undefined,
  tz: TimezoneChoice,
  sourceZone?: string | null,
): string {
  const wallClock = wallClockOf(value, sourceZone);
  if (wallClock) return `${wallClock.slice(0, 19)} 현지(미확정)`;
  const date = parseInstant(value);
  if (!date) return value === null || value === undefined || value === "" ? "" : String(value);
  return `${formatTimestamp(date, tz)} ${zoneShort(tz, date)}`;
}

// ---------------------------------------------------------------------------
// Ranges and typed times (filter chips, 시간 개요 띠, palette, action dialogs): the same
// `YYYY-MM-DD HH:mm` reading in the console's display zone as the grid, the zone named once.
// ---------------------------------------------------------------------------

/** "2026-10-22 13:45 KST" (`zone: false` drops the zone name). */
export function formatMinute(ms: number, tz: TimezoneChoice, options: { zone?: boolean } = {}): string {
  const date = new Date(ms);
  const text = formatTimestamp(date, tz, { precision: "minute" });
  return options.zone === false ? text : `${text} ${zoneShort(tz, date)}`;
}

/** "10-22 13:45": month-day and clock in the display zone (a strip axis next to a full range). */
export function formatShortMinute(ms: number, tz: TimezoneChoice): string {
  return formatTimestamp(new Date(ms), tz, { precision: "minute" }).slice(5);
}

/**
 * "2026-10-22 13:45 ~ 14:59 KST" — the end's date only when it differs from the start's
 * ("2026-10-22 00:00 ~ 2026-10-23 23:59 KST"); an open end reads "…".
 */
export function formatTimeRange(fromMs: number | null, toMs: number | null, tz: TimezoneChoice): string {
  if (fromMs === null && toMs === null) return "";
  const zoneAt = new Date(toMs ?? fromMs ?? 0);
  const from = fromMs === null ? "…" : formatMinute(fromMs, tz, { zone: false });
  let to = toMs === null ? "…" : formatMinute(toMs, tz, { zone: false });
  if (fromMs !== null && toMs !== null && from.slice(0, 10) === to.slice(0, 10)) to = to.slice(11);
  return `${from} ~ ${to} ${zoneShort(tz, zoneAt)}`;
}

/**
 * The instant of a wall-clock time in the display zone, or null when that time does not exist
 * there (a daylight-saving gap) or the parts are out of range (2월 30일, 25시).
 */
export function wallClockToMs(
  tz: TimezoneChoice,
  year: number,
  month: number,
  day: number,
  hour = 0,
  minute = 0,
  second = 0,
): number | null {
  const asUtc = Date.UTC(year, month - 1, day, hour, minute, second);
  if (Number.isNaN(asUtc)) return null;
  // Two passes: the offset at the first guess, then at the corrected instant (a DST edge).
  let ms = asUtc - tzOffsetMinutes(tz, new Date(asUtc)) * 60_000;
  ms = asUtc - tzOffsetMinutes(tz, new Date(ms)) * 60_000;
  const w = wallClock(new Date(ms), tz);
  const same =
    w.year === year &&
    w.month === month &&
    w.day === day &&
    w.hour === hour &&
    w.minute === minute &&
    w.second === second;
  return same ? ms : null;
}

/** Midnight of `ms`'s day in the display zone. */
export function startOfDayMs(ms: number, tz: TimezoneChoice): number {
  const w = wallClock(new Date(ms), tz);
  return (
    wallClockToMs(tz, w.year ?? 1970, w.month ?? 1, w.day ?? 1) ??
    ms - ((w.hour ?? 0) * 3600 + (w.minute ?? 0) * 60 + (w.second ?? 0)) * 1000 - (ms % 1000)
  );
}

/** `YYYY-MM-DDTHH:mm` of a bound in the display zone (the value of `<input type="datetime-local">`). */
export function toZonedInput(value: string | undefined, tz: TimezoneChoice): string {
  if (!value) return "";
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? "" : formatTimestamp(new Date(ms), tz, { precision: "minute" }).replace(" ", "T");
}

/**
 * A filter bound at minute precision: a UTC instant written to the minute (`…T05:00Z`), so a
 * `to` bound still covers that whole minute (rowConditions `boundUnitMs`).
 */
export function minuteBound(ms: number): string {
  return `${new Date(ms).toISOString().slice(0, 16)}Z`;
}

/** A filter bound from a `datetime-local` value read in the display zone; unreadable → undefined. */
export function zonedInputToBound(value: string, tz: TimezoneChoice): string | undefined {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(value);
  if (!match) return undefined;
  const [y, mo, d, h, mi] = match.slice(1).map(Number) as [number, number, number, number, number];
  const ms = wallClockToMs(tz, y, mo, d, h, mi);
  return ms === null ? undefined : minuteBound(ms);
}

/** Tooltip of an evidence time: the reading, the source text, the exact UTC and the FILETIME
 * (labelled 원문 only when the source value is exact, else 환산). */
export function evidenceTimeTooltip(
  value: string | number | Date | null | undefined,
  tz: TimezoneChoice,
  rawFiletime?: string | number | null,
  sourceZone?: string | null,
): string {
  const reading = exactEvidenceTime(value, tz, { sourceZone, rawFiletime });
  if (!reading) return value === null || value === undefined ? "" : String(value);
  const raw = value instanceof Date ? value.toISOString() : String(value);
  if (reading.zoneStatus === "wall-clock-zone-undetermined") {
    return [reading.display, `원문 ${raw} (${sourceZone})`, zoneStatusLabel(reading.zoneStatus)].join("\n");
  }
  const filetime =
    reading.filetimeBasis === "source"
      ? `FILETIME 원문 ${reading.filetime}`
      : `FILETIME(환산) ${reading.filetime ?? "—"}`;
  return [reading.display, `원문 ${raw}`, `UTC ${reading.exactUtc}`, filetime].join("\n");
}
