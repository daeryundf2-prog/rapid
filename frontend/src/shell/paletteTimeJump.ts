/** Palette entries for a typed date / date-time (fe-audit A2): open the timeline there. */

import { focusGridWhenReady } from "../commands/builtin";
import { jumpRange, parseJumpTime, toIsoBounds } from "../features/views/timelineRange";
import { useAppStore } from "../state/store";
import { formatMinute, type TimezoneChoice, zoneShort } from "../utils/time";
import type { PaletteItem } from "./paletteGroups";

/**
 * "2026-04-18 14:30" → 타임라인 ±30분; "2026-04-18" → 그날 하루, read and named in the display
 * zone like the grid ("타임라인: 2026-04-18 14:30 KST 전후 30분 보기").
 */
export function timeJumpItems(query: string, runId: string | null, tz: TimezoneChoice): PaletteItem[] {
  const jump = parseJumpTime(query, tz);
  if (!jump) return [];
  const range = jumpRange(jump);
  const { from, to } = toIsoBounds(range);
  const when =
    jump.precision === "day"
      ? `${formatMinute(jump.ms, tz, { zone: false }).slice(0, 10)} (${zoneShort(tz, new Date(jump.ms))})`
      : formatMinute(jump.ms, tz);
  return [
    {
      key: "timeline.jump",
      label: jump.precision === "day" ? `타임라인: ${when} 하루 보기` : `타임라인: ${when} 전후 30분 보기`,
      group: "navigate",
      icon: "clock",
      disabledReason: runId ? undefined : "케이스를 먼저 선택하세요",
      score: Number.POSITIVE_INFINITY,
      perform: () => {
        if (!runId) return;
        useAppStore.getState().navigate({ runId, collection: "timeline", from, to });
        focusGridWhenReady();
      },
    },
  ];
}
