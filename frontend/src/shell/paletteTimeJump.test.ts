import { describe, expect, it } from "vitest";
import { timeJumpItems } from "./paletteTimeJump";

describe("palette time jump (fe-audit A2) in the display zone", () => {
  it("reads and names a typed time in the display zone, like the grid", () => {
    const [seoul] = timeJumpItems("2026-10-22 14:00", "run1", "Asia/Seoul");
    expect(seoul?.label).toBe("타임라인: 2026-10-22 14:00 KST 전후 30분 보기");
    const [utc] = timeJumpItems("2026-10-22 14:00", "run1", "utc");
    expect(utc?.label).toBe("타임라인: 2026-10-22 14:00 UTC 전후 30분 보기");
  });

  it("names a date alone as that day, with the zone", () => {
    const [day] = timeJumpItems("2026-10-22", "run1", "Asia/Seoul");
    expect(day?.label).toBe("타임라인: 2026-10-22 (KST) 하루 보기");
  });

  it("offers nothing for text that is not a time, and is disabled without a case", () => {
    expect(timeJumpItems("invoice", "run1", "utc")).toEqual([]);
    expect(timeJumpItems("2026-10-22", null, "utc")[0]?.disabledReason).toBe("케이스를 먼저 선택하세요");
  });
});
