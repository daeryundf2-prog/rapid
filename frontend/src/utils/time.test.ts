import { describe, expect, it } from "vitest";
import { formatTimestamp, isValidTimezone, shiftIso, tzOffsetLabel } from "./time";

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
