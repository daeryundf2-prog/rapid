import { describe, expect, it } from "vitest";
import {
  formatGridTime,
  formatMinute,
  formatShortMinute,
  formatTimeRange,
  formatTimestamp,
  headerZone,
  headerZoneParts,
  isValidTimezone,
  minuteBound,
  shiftIso,
  startOfDayMs,
  toZonedInput,
  tzOffsetLabel,
  wallClockToMs,
  zonedInputToBound,
  zoneShort,
} from "./time";

describe("formatTimestamp", () => {
  const iso = "2026-03-01T15:30:45.123Z";
  it("formats in UTC and IANA zones", () => {
    expect(formatTimestamp(iso, "utc")).toBe("2026-03-01 15:30:45");
    expect(formatTimestamp(iso, "Asia/Seoul")).toBe("2026-03-02 00:30:45");
    expect(formatTimestamp(iso, "America/New_York")).toBe("2026-03-01 10:30:45");
  });
  it("honours precision", () => {
    expect(formatTimestamp(iso, "utc", { precision: "date" })).toBe("2026-03-01");
    expect(formatTimestamp(iso, "utc", { precision: "minute" })).toBe("2026-03-01 15:30");
    expect(formatTimestamp(iso, "utc", { precision: "ms" })).toBe("2026-03-01 15:30:45.123");
  });
  it("treats naive text as UTC, accepts epoch seconds, passes junk through", () => {
    expect(formatTimestamp("2026-03-01 15:30:45", "Asia/Seoul")).toBe("2026-03-02 00:30:45");
    expect(formatTimestamp(1772379045, "utc")).toBe("2026-03-01 15:30:45");
    expect(formatTimestamp("not a date", "utc")).toBe("not a date");
    expect(formatTimestamp(null, "utc")).toBe("—");
  });
  it("falls back to UTC for an invalid zone", () => {
    expect(isValidTimezone("Mars/Base")).toBe(false);
    expect(formatTimestamp(iso, "Mars/Base")).toBe("2026-03-01 15:30:45");
  });
  it("labels offsets", () => {
    const at = new Date(iso);
    expect(tzOffsetLabel("utc", at)).toBe("UTC+00:00");
    expect(tzOffsetLabel("Asia/Seoul", at)).toBe("UTC+09:00");
    expect(tzOffsetLabel("America/New_York", at)).toBe("UTC-05:00");
  });
  it("shifts by an hour", () => {
    expect(shiftIso(iso, -3_600_000)).toBe("2026-03-01T14:30:45.123Z");
    expect(shiftIso("zzz", 1)).toBeNull();
  });
});

describe("range and typed-time readings in the display zone", () => {
  const at = Date.UTC(2026, 9, 22, 4, 45, 30); // 13:45:30 KST

  it("names the zone shortly", () => {
    expect(zoneShort("Asia/Seoul", new Date(at))).toBe("KST");
    expect(zoneShort("utc", new Date(at))).toBe("UTC");
    expect(zoneShort("Asia/Kolkata", new Date(at))).toMatch(/^(IST|UTC\+05:30)$/);
  });

  it("formats a minute, with or without the zone, and a short axis label", () => {
    expect(formatMinute(at, "Asia/Seoul")).toBe("2026-10-22 13:45 KST");
    expect(formatMinute(at, "utc", { zone: false })).toBe("2026-10-22 04:45");
    expect(formatShortMinute(at, "Asia/Seoul")).toBe("10-22 13:45");
  });

  it("writes a range's shared date once and an open end as …", () => {
    const later = at + 74 * 60_000;
    expect(formatTimeRange(at, later, "Asia/Seoul")).toBe("2026-10-22 13:45 ~ 14:59 KST");
    expect(formatTimeRange(at, at + 86_400_000, "utc")).toBe("2026-10-22 04:45 ~ 2026-10-23 04:45 UTC");
    expect(formatTimeRange(null, at, "utc")).toBe("… ~ 2026-10-22 04:45 UTC");
    expect(formatTimeRange(null, null, "utc")).toBe("");
  });

  it("finds the instant of a wall clock, refusing times that do not exist there", () => {
    expect(wallClockToMs("Asia/Seoul", 2026, 10, 22, 13, 45)).toBe(Date.UTC(2026, 9, 22, 4, 45));
    expect(wallClockToMs("utc", 2026, 2, 30)).toBeNull();
    expect(wallClockToMs("utc", 2026, 4, 18, 25)).toBeNull();
    // Spring forward in New York skips 02:00–03:00; the hour after the gap is EDT (UTC−4).
    expect(wallClockToMs("America/New_York", 2026, 3, 8, 2, 30)).toBeNull();
    expect(wallClockToMs("America/New_York", 2026, 3, 8, 3, 30)).toBe(Date.UTC(2026, 2, 8, 7, 30));
  });

  it("finds the display zone's midnight", () => {
    expect(startOfDayMs(at, "Asia/Seoul")).toBe(Date.UTC(2026, 9, 21, 15));
    expect(startOfDayMs(at, "utc")).toBe(Date.UTC(2026, 9, 22));
  });

  it("round-trips a datetime-local value through a UTC minute bound", () => {
    expect(minuteBound(at)).toBe("2026-10-22T04:45Z");
    expect(toZonedInput("2026-10-22T04:45Z", "Asia/Seoul")).toBe("2026-10-22T13:45");
    expect(toZonedInput(undefined, "utc")).toBe("");
    expect(toZonedInput("nope", "utc")).toBe("");
    expect(zonedInputToBound("2026-10-22T13:45", "Asia/Seoul")).toBe("2026-10-22T04:45Z");
    expect(zonedInputToBound("2026-10-2", "utc")).toBeUndefined();
  });
});

describe("time cells under a header that names the zone", () => {
  const hidden = (text: string, zone: string) =>
    headerZoneParts(text, zone)
      .map((part) => (part.zone ? `[${part.text}]` : part.text))
      .join("");

  it("names the display zone of the header now", () => {
    expect(headerZone("Asia/Seoul")).toBe("KST");
    expect(headerZone("utc")).toBe("UTC");
    expect(headerZone("America/New_York", new Date(Date.UTC(2026, 0, 1)))).toBe("EST");
  });

  it("splits off the header's zone after each time; the parts join back to the full reading", () => {
    const one = formatGridTime("2026-10-18T00:02:48Z", "Asia/Seoul");
    expect(hidden(one, "KST")).toBe("2026-10-18 09:02:48[ KST]");
    expect(
      headerZoneParts(one, "KST")
        .map((part) => part.text)
        .join(""),
    ).toBe(one);
    // A list of times (Prefetch run times) hides each; a fraction stays with its time.
    expect(hidden("2026-10-18 09:02:48 KST, 2026-10-19 10:00:00.1234567 KST", "KST")).toBe(
      "2026-10-18 09:02:48[ KST], 2026-10-19 10:00:00.1234567[ KST]",
    );
    expect(hidden("2026-10-18 09:02 UTC+05:30", "UTC+05:30")).toBe("2026-10-18 09:02[ UTC+05:30]");
  });

  it("keeps a zone that is not the header's, an undetermined wall clock and other text whole", () => {
    // Summer half of a daylight-saving zone under a winter header.
    expect(hidden("2026-07-01 08:00:00 EDT", "EST")).toBe("2026-07-01 08:00:00 EDT");
    expect(hidden("2026-07-01 08:00:00 현지(미확정)", "KST")).toBe("2026-07-01 08:00:00 현지(미확정)");
    expect(hidden("KST office", "KST")).toBe("KST office");
    expect(hidden("", "KST")).toBe("");
  });
});
