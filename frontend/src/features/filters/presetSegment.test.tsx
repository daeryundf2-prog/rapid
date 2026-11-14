// R7 stage 1 re-review R-6: "증거 기준 최근 7일/30일" overflowed the condition popover (338/475).
// The anchor prefix is shown once above the segment; the buttons carry short labels and keep the
// full label as their accessible name.
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { relativePresetCaption, relativePresetShortLabel } from "./conditionValues";
import { PresetButtons } from "./FilterBar";
import { EMPTY_FILTERS } from "./filterModel";
import { useFilterStore } from "./filterStore";

const evidence = { ms: Date.parse("2025-03-10T09:00:00Z"), source: "evidence" as const };

beforeEach(() => useFilterStore.getState().patchFilters({ ...EMPTY_FILTERS }));
afterEach(cleanup);

describe("R-6: preset segment fits the popover", () => {
  it("short labels and a one-time caption per anchor", () => {
    expect(relativePresetShortLabel("7d", evidence)).toBe("최근 7일");
    expect(relativePresetShortLabel("today", evidence)).toBe("마지막 날");
    expect(relativePresetShortLabel("today", { ms: 0, source: "now" })).toBe("오늘");
    expect(relativePresetCaption(evidence)).toBe("증거 기준");
    expect(relativePresetCaption({ ms: 0, source: "run-start" })).toBe("런 시작 기준");
    expect(relativePresetCaption({ ms: 0, source: "now" })).toBe("");
  });

  it("shows 증거 기준 once above the buttons; each button keeps the full accessible name", () => {
    render(<PresetButtons anchor={evidence} />);
    expect(screen.getByTestId("relative-presets-caption").textContent).toBe("증거 기준");
    const segment = screen.getByTestId("relative-presets");
    const buttons = within(segment).getAllByRole("button");
    for (const button of buttons) expect(button.textContent).not.toContain("증거 기준");
    expect(buttons.map((b) => b.getAttribute("aria-label"))).toEqual(
      expect.arrayContaining(["증거 기준 최근 7일", "증거 기준 최근 30일"]),
    );
    expect(segment.classList.contains("filter-preset-segment")).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "증거 기준 최근 7일" }));
    expect(useFilterStore.getState().filters.from).toBeTruthy();
  });

  it("no caption when counted from the clock", () => {
    render(<PresetButtons anchor={{ ms: Date.now(), source: "now" }} />);
    expect(screen.queryByTestId("relative-presets-caption")).toBeNull();
    expect(screen.getByRole("button", { name: "최근 7일" })).toBeTruthy();
  });
});
