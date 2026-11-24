import { describe, expect, it } from "vitest";
import { formatGridTime, zoneLabel } from "./time";

// D19 #10: the daylight/standard abbreviation follows the zone's own offset at that instant.
// January is daylight time in Sydney; a January-is-standard rule swapped AEST and AEDT.
describe("zone abbreviations in both hemispheres (D19 #10)", () => {
  const january = new Date("2024-01-15T00:00:00Z");
  const july = new Date("2024-07-15T00:00:00Z");

  it("Sydney: AEDT +11:00 in January, AEST +10:00 in July", () => {
    expect(zoneLabel("Australia/Sydney", january)).toBe("AEDT+11:00");
    expect(zoneLabel("Australia/Sydney", july)).toBe("AEST+10:00");
    expect(formatGridTime(january.toISOString(), "Australia/Sydney")).toBe("2024-01-15 11:00:00 AEDT");
    expect(formatGridTime(july.toISOString(), "Australia/Sydney")).toBe("2024-07-15 10:00:00 AEST");
  });

  it("New York: EST -05:00 in January, EDT -04:00 in July", () => {
    expect(zoneLabel("America/New_York", january)).toBe("EST-05:00");
    expect(zoneLabel("America/New_York", july)).toBe("EDT-04:00");
    expect(formatGridTime(january.toISOString(), "America/New_York")).toBe("2024-01-14 19:00:00 EST");
    expect(formatGridTime(july.toISOString(), "America/New_York")).toBe("2024-07-14 20:00:00 EDT");
  });

  it("zones without daylight time keep their single abbreviation", () => {
    expect(zoneLabel("Asia/Seoul", january)).toBe("KST+09:00");
    expect(zoneLabel("Asia/Seoul", july)).toBe("KST+09:00");
  });
});
