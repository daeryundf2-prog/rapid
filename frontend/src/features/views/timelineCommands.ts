/**
 * Range actions of the timeline's 시간 개요 띠: apply / pan / widen a range through the filter
 * store (route `from`/`to`), and the `[` `]` `-` commands registered while the strip is on
 * screen (the dispatcher owns the keys; the commands own the action).
 */

import { type RefObject, useEffect } from "react";
import { announce } from "../../a11y";
import { registerCommands } from "../../commands/registry";
import { KEY_MAP } from "../../contracts/command";
import { useAppStore } from "../../state/store";
import { setTimeRange } from "../filters/filterStore";
import { type MsRange, panRange, toIsoBounds, zoomOutRange } from "./timelineRange";

const NOT_TIMELINE = "타임라인에서만 쓸 수 있습니다";
const NO_RANGE = "먼저 시간 범위를 고르세요 (막대를 누르거나 시각을 입력)";

export interface StripState {
  range: MsRange | null;
  extent: MsRange | null;
}

export function applyRange(range: MsRange | null, message: string): void {
  if (range) {
    const { from, to } = toIsoBounds(range);
    setTimeRange(from, to);
  } else {
    setTimeRange(undefined, undefined);
  }
  announce(message);
}

/** Local month/day hour:minute, the strip's time label. */
export const fmt = (ms: number) =>
  new Date(ms).toLocaleString("ko-KR", {
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

export function useTimelineCommands(live: RefObject<StripState>): void {
  useEffect(() => {
    const reason = () => {
      if (useAppStore.getState().route.collection !== "timeline") return NOT_TIMELINE;
      return live.current.range && live.current.extent ? undefined : NO_RANGE;
    };
    const pan = (direction: -1 | 1) => {
      const { range: r, extent: e } = live.current;
      if (r && e) {
        const next = panRange(r, direction, e);
        applyRange(next, `${direction < 0 ? "이전" : "다음"} 구간: ${fmt(next.fromMs)} ~ ${fmt(next.toMs)}`);
      }
    };
    return registerCommands([
      {
        id: "timeline.prev",
        label: "타임라인: 이전 구간",
        group: "grid",
        icon: "chevron-left",
        shortcut: KEY_MAP.timelinePrev,
        disabledReason: reason,
        run: () => pan(-1),
      },
      {
        id: "timeline.next",
        label: "타임라인: 다음 구간",
        group: "grid",
        icon: "chevron-right",
        shortcut: KEY_MAP.timelineNext,
        disabledReason: reason,
        run: () => pan(1),
      },
      {
        id: "timeline.zoom-out",
        label: "타임라인: 범위 넓히기",
        group: "grid",
        icon: "clock",
        shortcut: KEY_MAP.timelineZoomOut,
        disabledReason: reason,
        run: () => {
          const { range: r, extent: e } = live.current;
          if (!r || !e) return;
          const next = zoomOutRange(r, e);
          applyRange(
            next,
            next ? `범위를 넓혔습니다: ${fmt(next.fromMs)} ~ ${fmt(next.toMs)}` : "전체 기간을 봅니다",
          );
        },
      },
    ]);
  }, [live.current.range, live.current.extent, live.current]);
}
