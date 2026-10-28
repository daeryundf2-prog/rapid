import { describe, expect, it } from "vitest";
import { type QueueItem, queueAnnouncement, stepUnreviewed } from "./queue";

const items = (...flags: boolean[]): QueueItem[] => flags.map((reviewed, i) => ({ key: `r${i}`, reviewed }));

describe("review queue navigation", () => {
  it("moves to the next unreviewed item and skips reviewed ones", () => {
    const list = items(false, true, false, false);
    expect(stepUnreviewed(list, "r0", 1)).toEqual({ key: "r2", ordinal: 2, total: 3 });
    expect(stepUnreviewed(list, "r2", 1)).toEqual({ key: "r3", ordinal: 3, total: 3 });
  });

  it("moves to the previous unreviewed item", () => {
    const list = items(false, true, false, true);
    expect(stepUnreviewed(list, "r3", -1)).toEqual({ key: "r2", ordinal: 2, total: 2 });
  });

  it("wraps at both ends", () => {
    const list = items(false, true, false);
    expect(stepUnreviewed(list, "r2", 1)).toEqual({ key: "r0", ordinal: 1, total: 2 });
    expect(stepUnreviewed(list, "r0", -1)).toEqual({ key: "r2", ordinal: 2, total: 2 });
  });

  it("starts from the top or bottom when no current row is in the list", () => {
    const list = items(true, false, false);
    expect(stepUnreviewed(list, null, 1)?.key).toBe("r1");
    expect(stepUnreviewed(list, "missing", -1)?.key).toBe("r2");
  });
});

describe("review queue none-left", () => {
  it("returns null and the 미검토 없음 sentence when every item is reviewed", () => {
    const list = items(true, true);
    expect(stepUnreviewed(list, "r0", 1)).toBeNull();
    expect(queueAnnouncement(stepUnreviewed(list, "r0", 1))).toBe("미검토 없음");
  });

  it("returns null for an empty view", () => {
    expect(stepUnreviewed([], null, 1)).toBeNull();
  });

  it("announces the k/n position otherwise", () => {
    const step = stepUnreviewed(items(false, false, true), null, 1);
    expect(queueAnnouncement(step)).toBe("미검토 1/2");
  });
});
