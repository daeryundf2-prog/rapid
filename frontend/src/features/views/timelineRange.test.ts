import { describe, expect, it } from "vitest";
import type { TimelineHistogramPayload } from "./histogram";
import {
  extentOf,
  jumpRange,
  panRange,
  parseJumpTime,
  rangeFromBounds,
  stripBars,
  windowAround,
  zoomOutRange,
} from "./timelineRange";

const HOUR = 3_600_000;
const DAY = 86_400_000;
const T0 = Date.UTC(2026, 3, 14, 0, 0, 0);

/** Hour buckets: 10 events at T0, 5 at T0+1h, 3 at T0+5d. */
function payload(): TimelineHistogramPayload {
  const bucket = (offsetMs: number, count: number, index: number) => ({
    index,
    start: new Date(T0 + offsetMs).toISOString(),
    end: new Date(T0 + offsetMs + HOUR).toISOString(),
    count,
  });
  return {
    total_events: 18,
    parsed_events: 18,
    unparsed_events: 0,
    bucket_seconds: 3600,
    bucket_count: 3,
    range_start: new Date(T0).toISOString(),
    range_end: new Date(T0 + 5 * DAY + HOUR).toISOString(),
    sources: [],
    buckets: [bucket(0, 10, 0), bucket(HOUR, 5, 1), bucket(5 * DAY, 3, 2)],
  };
}

describe("timeline strip bars", () => {
  it("count every event once over the whole span, and draw a zoomed window's own buckets", () => {
    const data = payload();
    const extent = extentOf(data);
    expect(extent).toEqual({ fromMs: T0, toMs: T0 + 5 * DAY + HOUR - 1 });
    const whole = stripBars(data, null, extent, "utc");
    expect(whole.granularity).toBe("day");
    expect(whole.buckets.reduce((sum, b) => sum + b.count, 0)).toBe(18);
    // A range draws the server buckets of that window (here the hour buckets), clipped to it.
    const zoomed = stripBars(data, { fromMs: T0, toMs: T0 + 2 * HOUR - 1 }, extent, "utc");
    expect(zoomed.granularity).toBe("native");
    expect(zoomed.buckets.map((b) => b.count)).toEqual([10, 5]);
  });

  it("lay a zoomed window's unit over the whole range, so the axis spans what the header names", () => {
    const data = payload();
    const extent = extentOf(data);
    // The server stops at the last event's bucket; the strip pads empty bars before and after.
    const zoomed = stripBars(data, { fromMs: T0 - 2 * HOUR, toMs: T0 + 4 * HOUR - 1 }, extent, "utc");
    expect(zoomed.buckets.map((b) => b.count)).toEqual([0, 0, 10, 5, 0, 0]);
    expect(zoomed.buckets[0]?.startMs).toBe(T0 - 2 * HOUR);
    expect(zoomed.buckets.at(-1)?.endMs).toBe(T0 + 4 * HOUR);
  });

  it("put day bars on the display zone's midnights", () => {
    const data = payload();
    const extent = extentOf(data);
    const seoul = stripBars(data, null, extent, "Asia/Seoul");
    // T0 is 09:00 KST, so the first bar starts at 00:00 KST = 15:00Z the day before.
    expect(seoul.buckets[0]?.startMs).toBe(T0 - 9 * HOUR);
    expect(seoul.buckets.reduce((sum, b) => sum + b.count, 0)).toBe(18);
  });

  it("an open bound of the route takes the extent's edge; a reversed range is none", () => {
    const extent = { fromMs: 0, toMs: 1000 };
    expect(rangeFromBounds(new Date(500).toISOString(), undefined, extent)).toEqual({
      fromMs: 500,
      toMs: 1000,
    });
    expect(rangeFromBounds(undefined, undefined, extent)).toBeNull();
    expect(rangeFromBounds(new Date(900).toISOString(), new Date(100).toISOString(), extent)).toBeNull();
  });
});

describe("range steps", () => {
  const extent = { fromMs: 0, toMs: 10 * HOUR - 1 };
  it("pan keeps the width and stops at the extent", () => {
    const hour = { fromMs: 2 * HOUR, toMs: 3 * HOUR - 1 };
    expect(panRange(hour, 1, extent)).toEqual({ fromMs: 3 * HOUR, toMs: 4 * HOUR - 1 });
    expect(panRange(hour, -1, extent)).toEqual({ fromMs: HOUR, toMs: 2 * HOUR - 1 });
    expect(panRange({ fromMs: 9 * HOUR, toMs: 10 * HOUR - 1 }, 1, extent)).toEqual({
      fromMs: 9 * HOUR,
      toMs: 10 * HOUR - 1,
    });
  });

  it("zoom out triples around the centre and clears once it covers everything", () => {
    const next = zoomOutRange({ fromMs: 4 * HOUR, toMs: 5 * HOUR - 1 }, extent);
    expect(next).toEqual({ fromMs: 3 * HOUR, toMs: 6 * HOUR - 1 });
    expect(zoomOutRange({ fromMs: 0, toMs: 6 * HOUR }, extent)).toBeNull();
  });

  it("a window around an instant is inclusive on both ends", () => {
    expect(windowAround(HOUR, 60_000)).toEqual({ fromMs: HOUR - 60_000, toMs: HOUR + 60_000 - 1 });
  });
});

describe("typed jump times", () => {
  it("read a date as its day in the display zone and a clock time as ±30 minutes", () => {
    const day = parseJumpTime("2026-04-18", "local");
    expect(day).toEqual({ ms: new Date(2026, 3, 18).getTime(), precision: "day" });
    expect(day && jumpRange(day)).toEqual({
      fromMs: new Date(2026, 3, 18).getTime(),
      toMs: new Date(2026, 3, 19).getTime() - 1,
    });
    const minute = parseJumpTime(" 2026.4.18 14:30 ", "local");
    expect(minute).toEqual({ ms: new Date(2026, 3, 18, 14, 30).getTime(), precision: "minute" });
    expect(minute && jumpRange(minute).toMs - jumpRange(minute).fromMs).toBe(60 * 60_000 - 1);
    expect(parseJumpTime("2026-04-18T09:05:07", "local")?.ms).toBe(new Date(2026, 3, 18, 9, 5, 7).getTime());
    // The same text is a different instant in another display zone.
    expect(parseJumpTime("2026-04-18 09:00", "utc")?.ms).toBe(Date.UTC(2026, 3, 18, 9));
    expect(parseJumpTime("2026-04-18 09:00", "Asia/Seoul")?.ms).toBe(Date.UTC(2026, 3, 18, 0));
  });

  it("refuse anything that is not a real calendar time", () => {
    for (const text of ["", "invoice", "2026-02-30", "2026-04-18 25:00", "2026-04-18 10:61", "18-04-2026"]) {
      expect(parseJumpTime(text, "utc")).toBeNull();
    }
    // 02:30 does not exist on the spring-forward day in New York.
    expect(parseJumpTime("2026-03-08 02:30", "America/New_York")).toBeNull();
  });
});
