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
  // Daylight abbreviation when the offset is past the zone's January (standard) offset.
  const january = tzOffsetMinutes(name, new Date(Date.UTC(date.getUTCFullYear(), 0, 15)));
  const label = abbr[1] && minutes !== january ? abbr[1] : abbr[0];
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

/** Grid cells: "2025-05-29 23:25:26 KST" — seconds, the zone named (the tooltip has the rest). */
export function formatGridTime(value: string | number | Date | null | undefined, tz: TimezoneChoice): string {
  const date = parseInstant(value);
  if (!date) return value === null || value === undefined || value === "" ? "" : String(value);
  const zone = zoneLabel(tz, date);
  const short = zone === "UTC" ? "UTC" : zone.replace(/[+-]\d{2}:\d{2}$/, "") || zone;
  return `${formatTimestamp(date, tz)} ${short}`;
}

// ---------------------------------------------------------------------------
// Run identity times (R7 L1, C-G3/C-G4): one format for a run's start / end on every screen —
// 랜딩 · 처리 · 접수 · 케이스 선택기 · 케이스 열기 print the same string for the same run.
// ---------------------------------------------------------------------------

/** "2026-10-17 20:18" — a run's start / end (minute precision) in the display zone; "—" when missing. */
export function formatRunTime(value: string | number | Date | null | undefined, tz: TimezoneChoice): string {
  return formatTimestamp(value, tz, { precision: "minute" });
}

/** Windows zone names (registry `TimeZoneKeyName`) → IANA, for the evidence-system zone option. */
const WINDOWS_ZONES: Record<string, string> = {
  "Korea Standard Time": "Asia/Seoul",
  "Tokyo Standard Time": "Asia/Tokyo",
  "China Standard Time": "Asia/Shanghai",
  "Taipei Standard Time": "Asia/Taipei",
  "Singapore Standard Time": "Asia/Singapore",
  UTC: "UTC",
  "Coordinated Universal Time": "UTC",
  "GMT Standard Time": "Europe/London",
  "W. Europe Standard Time": "Europe/Berlin",
  "Romance Standard Time": "Europe/Paris",
  "Eastern Standard Time": "America/New_York",
  "Central Standard Time": "America/Chicago",
  "Mountain Standard Time": "America/Denver",
  "Pacific Standard Time": "America/Los_Angeles",
  "AUS Eastern Standard Time": "Australia/Sydney",
};

export interface EvidenceZoneOption {
  /** Display-zone choice: an IANA name, or a fixed "Etc/GMT±N" from the bias. */
  value: string;
  /** "증거 시스템(KST −540)". */
  label: string;
}

/**
 * The status-bar option for the evidence system's zone (P6): the Windows name mapped to IANA,
 * else a fixed offset from the bias (whole hours only); null when neither is usable.
 */
export function evidenceZoneOption(
  zone: { name?: string | null; bias_minutes?: number | null } | null | undefined,
): EvidenceZoneOption | null {
  if (!zone) return null;
  const bias =
    typeof zone.bias_minutes === "number" && Number.isFinite(zone.bias_minutes) ? zone.bias_minutes : null;
  let value = zone.name ? WINDOWS_ZONES[zone.name] : undefined;
  if (!value && zone.name?.includes("/") && isValidTimezone(zone.name)) value = zone.name;
  // Etc/GMT signs are inverted: UTC+09:00 (bias −540) is "Etc/GMT-9".
  if (!value && bias !== null && bias % 60 === 0)
    value = bias === 0 ? "UTC" : `Etc/GMT${bias > 0 ? "+" : "-"}${Math.abs(bias / 60)}`;
  if (!value || !isValidTimezone(value)) return null;
  const zone0 = zoneLabel(value);
  const abbr = zone0.replace(/[+-]\d{2}:\d{2}$/, "");
  const short = abbr && !abbr.startsWith("UTC") ? abbr : zone0;
  const biasText = bias === null ? "" : ` ${bias < 0 ? "−" : bias > 0 ? "+" : ""}${Math.abs(bias)}`;
  return { value, label: `증거 시스템(${short}${biasText})` };
}

/** Tooltip of an evidence time: the source text, the UTC ISO and the FILETIME (raw when known). */
export function evidenceTimeTooltip(
  value: string | number | Date | null | undefined,
  tz: TimezoneChoice,
  rawFiletime?: string | number | null,
): string {
  const reading = evidenceTime(value, tz);
  if (!reading) return value === null || value === undefined ? "" : String(value);
  const filetime =
    rawFiletime !== undefined && rawFiletime !== null && rawFiletime !== ""
      ? `FILETIME 원문 ${rawFiletime}`
      : `FILETIME(환산) ${filetimeOf(value) ?? "—"}`;
  return [reading.text, `원문 ${reading.raw}`, filetime].join("\n");
}
