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
    date = new Date(naive ? `${text.replace(" ", "T")}Z` : text);
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
