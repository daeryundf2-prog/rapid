/** Palette entries for a typed date / date-time (fe-audit A2): open the timeline there. */

import { focusGridWhenReady } from "../commands/builtin";
import { jumpRange, parseJumpTime, toIsoBounds } from "../features/views/timelineRange";
import { useAppStore } from "../state/store";
import type { PaletteItem } from "./paletteGroups";

/** "2026-04-18 14:30" → 타임라인 ±30분; "2026-04-18" → 그날 하루 (browser-local, like the range inputs). */
export function timeJumpItems(query: string, runId: string | null): PaletteItem[] {
  const jump = parseJumpTime(query);
  if (!jump) return [];
  const range = jumpRange(jump);
  const { from, to } = toIsoBounds(range);
  const when = new Date(jump.ms).toLocaleString(
    "ko-KR",
    jump.precision === "day" ? { dateStyle: "medium" } : { dateStyle: "medium", timeStyle: "short" },
  );
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
