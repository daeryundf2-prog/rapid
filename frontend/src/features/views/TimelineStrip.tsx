/**
 * 시간 개요 띠 (fe-audit A1/A2/D1): a compact histogram above the timeline grid that keeps the
 * list in place. Without a range it shows the whole timeline; with one (filter bar `from`/`to`)
 * it shows that range at a finer unit. A bar click zooms to that bar, a drag to the dragged
 * bars; `[` / `]` move to the previous / next range of the same width, `-` zooms out, and a
 * typed time ("2026-04-18 14:30" or a date) opens the 30 minutes around it or that day.
 * It shares the histogram view's query (`["timeline-histogram", runId]`).
 */

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { type KeyboardEvent, useMemo, useRef, useState } from "react";
import { announce } from "../../a11y";
import { runCommand } from "../../commands/registry";
import { KEY_MAP } from "../../contracts/command";
import { Icon } from "../../icons";
import { keyLabel } from "../../shortcuts";
import { setTimeRange, useFilterStore } from "../filters/filterStore";
import { fetchTimelineHistogram } from "./HistogramView";
import { rangeOf } from "./histogram";
import { TimelineJump } from "./TimelineJump";
import { applyRange, fmt, type StripState, useTimelineCommands } from "./timelineCommands";
import { extentOf, rangeFromBounds, stripBars, toIsoBounds } from "./timelineRange";

export function TimelineStrip({ runId }: { runId: string }) {
  const histogram = useQuery({
    queryKey: ["timeline-histogram", runId] as const,
    queryFn: ({ signal }) => fetchTimelineHistogram(runId, signal),
    staleTime: 60_000,
    retry: false,
  });
  const filters = useFilterStore((s) => s.filters);
  const extent = useMemo(() => (histogram.data ? extentOf(histogram.data) : null), [histogram.data]);
  const range = useMemo(
    () => rangeFromBounds(filters.from, filters.to, extent),
    [filters.from, filters.to, extent],
  );
  // A range gets its own histogram (finer server buckets); the previous bars stay while it loads.
  const zoomWindow = range ? toIsoBounds(range) : null;
  const zoom = useQuery({
    queryKey: ["timeline-histogram", runId, zoomWindow?.from, zoomWindow?.to] as const,
    queryFn: ({ signal }) => fetchTimelineHistogram(runId, signal, zoomWindow ?? undefined),
    enabled: zoomWindow !== null,
    staleTime: 60_000,
    retry: false,
    placeholderData: keepPreviousData,
  });
  const source = range ? (zoom.data ?? histogram.data) : histogram.data;
  const { buckets } = useMemo(
    () => (source ? stripBars(source, range, extent) : { granularity: "day" as const, buckets: [] }),
    [source, range, extent],
  );
  const max = Math.max(1, ...buckets.map((b) => b.count));
  const total = buckets.reduce((sum, b) => sum + b.count, 0);
  const [drag, setDrag] = useState<{ anchor: number; focus: number } | null>(null);
  const [active, setActive] = useState(0);
  const barsRef = useRef<HTMLDivElement>(null);
  const live = useRef<StripState>({ range, extent });
  live.current = { range, extent };

  useTimelineCommands(live);

  if (histogram.isPending)
    return (
      <div className="tl-strip tl-strip-loading" role="status">
        <span className="visually-hidden">시간 개요를 불러오는 중</span>
      </div>
    );
  if (histogram.error || !histogram.data || !extent || (!range && buckets.length === 0)) return null;

  const zoomTo = (a: number, b: number) => {
    const picked = rangeOf(buckets, a, b);
    if (!picked) return;
    const count = buckets.slice(Math.min(a, b), Math.max(a, b) + 1).reduce((sum, x) => sum + x.count, 0);
    setTimeRange(picked.from, picked.to);
    announce(`시간 범위를 좁혔습니다: ${count.toLocaleString("ko-KR")}건`);
  };

  const onBarKey = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const target = { ArrowRight: index + 1, ArrowLeft: index - 1, Home: 0, End: buckets.length - 1 }[
      event.key
    ];
    if (target !== undefined) {
      event.preventDefault();
      const next = Math.min(Math.max(target, 0), buckets.length - 1);
      setActive(next);
      barsRef.current?.querySelector<HTMLElement>(`[data-bar-index="${next}"]`)?.focus();
    }
  };

  const lo = drag ? Math.min(drag.anchor, drag.focus) : -1;
  const hi = drag ? Math.max(drag.anchor, drag.focus) : -1;
  const first = buckets[0];
  const last = buckets.at(-1);
  return (
    <section className="tl-strip" aria-label="시간 개요" data-testid="timeline-strip">
      <div className="tl-strip-bar">
        <span className="tl-strip-range" aria-live="polite">
          {range ? `${fmt(range.fromMs)} ~ ${fmt(range.toMs)}` : "전체 기간"} ·{" "}
          {total.toLocaleString("ko-KR")}건
        </span>
        <span className="tl-strip-actions">
          <button
            type="button"
            className="grid-btn icon-btn"
            aria-label="이전 구간"
            title={`이전 구간 (${keyLabel(KEY_MAP.timelinePrev)})`}
            disabled={!range}
            onClick={() => void runCommand("timeline.prev")}
          >
            <Icon name="chevron-left" />
          </button>
          <button
            type="button"
            className="grid-btn icon-btn"
            aria-label="다음 구간"
            title={`다음 구간 (${keyLabel(KEY_MAP.timelineNext)})`}
            disabled={!range}
            onClick={() => void runCommand("timeline.next")}
          >
            <Icon name="chevron-right" />
          </button>
          <button
            type="button"
            className="grid-btn"
            title={`범위 넓히기 (${keyLabel(KEY_MAP.timelineZoomOut)})`}
            disabled={!range}
            onClick={() => void runCommand("timeline.zoom-out")}
          >
            넓히기
          </button>
          <button
            type="button"
            className="grid-btn"
            disabled={!range}
            onClick={() => applyRange(null, "전체 기간을 봅니다")}
          >
            전체
          </button>
          <TimelineJump />
        </span>
      </div>
      {/* biome-ignore lint/a11y/useSemanticElements: a group of bar buttons, not a form fieldset */}
      <div ref={barsRef} className="tl-strip-bars" role="group" aria-label={`시간 막대 ${buckets.length}개`}>
        {buckets.length === 0 ? (
          <p className="tl-strip-empty">이 범위에는 시각이 있는 이벤트가 없습니다.</p>
        ) : null}
        {buckets.map((bucket, index) => {
          const label = `${fmt(bucket.startMs)} ~ ${fmt(bucket.endMs - 1)}, ${bucket.count.toLocaleString("ko-KR")}건`;
          return (
            <button
              key={bucket.startMs}
              type="button"
              className="tl-strip-col"
              data-bar-index={index}
              data-selected={index >= lo && index <= hi ? "" : undefined}
              aria-label={`${label} — 눌러서 이 구간 보기`}
              title={label}
              tabIndex={index === active ? 0 : -1}
              onFocus={() => setActive(index)}
              onKeyDown={(event) => onBarKey(event, index)}
              onMouseDown={(event) => {
                if (event.button === 0) setDrag({ anchor: index, focus: index });
              }}
              onMouseEnter={() => setDrag((d) => (d ? { ...d, focus: index } : d))}
              onMouseUp={() => {
                const anchor = drag?.anchor ?? index;
                setDrag(null);
                zoomTo(anchor, index);
              }}
              onClick={(event) => {
                // Keyboard activation (mouse clicks are handled on mouseup).
                if (event.detail === 0) zoomTo(index, index);
              }}
            >
              <span
                className="tl-strip-fill"
                style={{ height: `${bucket.count ? Math.max(8, (bucket.count / max) * 100) : 0}%` }}
              />
            </button>
          );
        })}
      </div>
      <div className="tl-strip-axis" aria-hidden="true">
        <span>{first ? fmt(first.startMs) : ""}</span>
        <span>{last ? fmt(last.endMs - 1) : ""}</span>
      </div>
    </section>
  );
}
