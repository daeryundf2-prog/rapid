/** 시간 개요 띠 axis (F-tables): day / hour labels in the display zone instead of two end labels. */
import { describe, expect, it } from "vitest";
import {
  axisTicks,
  bucketAriaLabel,
  bucketLabel,
  rebucket,
  type TimeBucket,
  type TimelineHistogramPayload,
} from "./histogram";
import { stripBars } from "./timelineRange";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

function bars(startIso: string, size: number, count: number): TimeBucket[] {
  const start = Date.parse(startIso);
  return Array.from({ length: count }, (_, i) => ({
    startMs: start + i * size,
    endMs: start + (i + 1) * size,
    count: 1,
  }));
}

describe("axisTicks", () => {
  it("labels every day bar when there is room (KST midnights)", () => {
    const days = bars("2026-10-17T15:00:00Z", DAY, 9); // 10-18 00:00 KST …
    expect(axisTicks(days, "Asia/Seoul", 16).map((t) => t.label)).toEqual([
      "10-18",
      "10-19",
      "10-20",
      "10-21",
      "10-22",
      "10-23",
      "10-24",
      "10-25",
      "10-26",
    ]);
  });

  it("thins day labels to fit (every 2nd, 3rd … bar) and adds the year across years", () => {
    const days = bars("2026-12-20T15:00:00Z", DAY, 20);
    const ticks = axisTicks(days, "Asia/Seoul", 5);
    expect(ticks.length).toBeLessThanOrEqual(5);
    expect(ticks.map((t) => t.index)).toEqual([0, 4, 8, 12, 16]);
    expect(ticks[0]?.label).toBe("2026-12-21");
  });

  it("hour bars: clock-aligned labels, a midnight reads its date", () => {
    const hours = bars("2026-10-18T09:00:00Z", HOUR, 30); // 18:00 KST … next day 23:00
    const ticks = axisTicks(hours, "Asia/Seoul", 6);
    expect(ticks.map((t) => t.label)).toEqual(["18시", "10-19", "06시", "12시", "18시"]);
  });

  it("nothing without bars or room", () => {
    expect(axisTicks([], "UTC", 10)).toEqual([]);
    expect(axisTicks(bars("2026-01-01T00:00:00Z", DAY, 3), "UTC", 0)).toEqual([]);
  });
});

describe("histogram view in the display zone (not UTC)", () => {
  const payload: TimelineHistogramPayload = {
    total_events: 3,
    parsed_events: 3,
    unparsed_events: 0,
    bucket_seconds: 3600,
    bucket_count: 3,
    range_start: null,
    range_end: null,
    sources: [],
    buckets: [
      // 10-18 23:30 KST and 10-19 00:30 KST: one UTC day, two KST days.
      { index: 0, start: "2026-10-18T14:00:00Z", end: "2026-10-18T15:00:00Z", count: 1 },
      { index: 1, start: "2026-10-18T15:00:00Z", end: "2026-10-18T16:00:00Z", count: 1 },
      { index: 2, start: "2026-10-22T15:00:00Z", end: "2026-10-22T16:00:00Z", count: 1 },
    ],
  };

  it("day bars start at the display zone's midnight", () => {
    const kst = rebucket(payload, "day", "Asia/Seoul");
    expect(new Date(kst.buckets[0]?.startMs ?? 0).toISOString()).toBe("2026-10-17T15:00:00.000Z");
    expect(kst.buckets.map((b) => b.count)).toEqual([1, 1, 0, 0, 0, 1]);
    expect(rebucket(payload, "day").buckets.map((b) => b.count)).toEqual([2, 0, 0, 0, 1]);
  });

  it("labels read in the zone, the zone named in the bar's label", () => {
    const ms = Date.parse("2026-10-18T15:00:00Z");
    expect(bucketLabel(ms, "day", "Asia/Seoul")).toBe("2026-10-19");
    expect(bucketLabel(ms, "hour", "Asia/Seoul")).toBe("10-19 00시");
    expect(bucketLabel(ms, "hour", "Asia/Kolkata")).toBe("10-18 20:30");
    expect(bucketAriaLabel({ startMs: ms, endMs: ms + HOUR, count: 2 }, "hour", "Asia/Seoul")).toBe(
      "10-19 00시 ~ 10-19 01시 (KST): 2건",
    );
  });

  it("the strip keeps KST day bars", () => {
    const extent = { fromMs: Date.parse("2026-10-18T14:00:00Z"), toMs: Date.parse("2026-10-22T15:59:59Z") };
    const { granularity, buckets } = stripBars(payload, null, extent, "Asia/Seoul");
    expect(granularity).toBe("day");
    expect(axisTicks(buckets, "Asia/Seoul", 10)[0]?.label).toBe("10-18");
  });
});

describe("review P2-3: day bars never regroup UTC server buckets into the wrong zone day", () => {
  const dayPayload = (): TimelineHistogramPayload => ({
    total_events: 0,
    parsed_events: 0,
    unparsed_events: 0,
    bucket_count: 0,
    range_start: null,
    range_end: null,
    sources: [],
    bucket_seconds: 86_400,
    buckets: Array.from({ length: 90 }, (_, i) => {
      const start = Date.parse("2026-08-01T00:00:00Z") + i * DAY;
      return {
        index: i,
        start: new Date(start).toISOString(),
        end: new Date(start + DAY).toISOString(),
        count: new Date(start).toISOString().startsWith("2026-10-20") ? 10 : 0,
      };
    }),
  });

  it("KST: keeps the server's UTC day bucket (exact span, click range = bar)", () => {
    const { granularity, buckets } = rebucket(dayPayload(), "auto", "Asia/Seoul");
    expect(granularity).toBe("native");
    const bar = buckets.find((b) => b.count === 10);
    expect(bar && new Date(bar.startMs).toISOString()).toBe("2026-10-20T00:00:00.000Z");
    expect(bar && new Date(bar.endMs).toISOString()).toBe("2026-10-21T00:00:00.000Z");
  });

  it("UTC display zone: the same buckets still make day bars", () => {
    expect(rebucket(dayPayload(), "auto", "UTC").granularity).toBe("day");
  });

  it("hour server buckets regroup into KST midnights (no bucket straddles one)", () => {
    const start = Date.parse("2026-10-20T14:00:00Z");
    const payload: TimelineHistogramPayload = {
      total_events: 0,
      parsed_events: 0,
      unparsed_events: 0,
      bucket_count: 0,
      range_start: null,
      range_end: null,
      sources: [],
      bucket_seconds: 3600,
      buckets: Array.from({ length: 4 }, (_, i) => ({
        index: i,
        start: new Date(start + i * HOUR).toISOString(),
        end: new Date(start + (i + 1) * HOUR).toISOString(),
        count: 1,
      })),
    };
    const { granularity, buckets } = rebucket(payload, "day", "Asia/Seoul");
    expect(granularity).toBe("day");
    expect(buckets.map((b) => b.count)).toEqual([1, 3]);
  });
});

describe("review P3-5: half-hour zones keep hour axis labels", () => {
  it("Asia/Kolkata hour bars (all at :30) get labels", () => {
    const hours = bars("2026-10-20T00:00:00Z", HOUR, 24);
    const ticks = axisTicks(hours, "Asia/Kolkata", 8);
    expect(ticks.length).toBeGreaterThan(0);
    expect(ticks.every((t) => t.label.endsWith(":30"))).toBe(true);
    expect(axisTicks(hours, "Asia/Seoul", 8).length).toBe(8);
  });
});
