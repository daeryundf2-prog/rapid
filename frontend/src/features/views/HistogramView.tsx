// biome-ignore-all lint/a11y/useSemanticElements: bar groups are role="group" containers of buttons, not form fieldsets
/**
 * 히스토그램 보기 (S9, plan X15).
 *
 * Timeline: time bars from GET /api/runs/{id}/timeline-histogram, fitted to the width (one bar
 * per 4 px, "자동") with edges and labels in the display timezone, limited to the time range
 * condition (R7 C-V2).
 * Click a bar or drag across bars → `rapidtriage:filter` {from, to} (see
 * filterEvent.ts), which S8's filter bar applies to the grid and the URL.
 * Keys: ←/→ move, Shift+←/→ extend the range, Home/End, Enter/Space apply,
 * Escape clears the pending range.
 *
 * Other collections: a category bar list — artifact kinds / artifact types
 * from the run tree counts, or extensions / types of the loaded rows (files,
 * docs, search). Clicking a bar opens the kind node or sets the type/ext filter.
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import { announce, useRovingTabindex } from "../../a11y";
import { api } from "../../api/client";
import { getRunTree } from "../../api/runs";
import type { GridRow } from "../../contracts/collection";
import { useRoute as useAppRoute, useTimezone } from "../../state/hooks";
import { tzOffsetMinutes, zoneLabel } from "../../utils/time";
import { useFilterStore } from "../filters/filterStore";
import { hasClock, timeWindow } from "../filters/rowConditions";
import { useRoute } from "../grid/adapter";
import { BaselineHistogram } from "../review/BaselineHistogram";
import { errorText } from "../viewer/useAsync";
import { emitTimeRangeFilter, toggleExtFilter, toggleTypeFilter } from "./filterEvent";
import {
  barSizeLabel,
  barsFromRows,
  barsFromTree,
  type CategoryBar,
  fitBuckets,
  GRANULARITY_LABELS,
  type GranularityChoice,
  maxBarsFor,
  rangeOf,
  type TimelineHistogramPayload,
  zonedBucketAriaLabel,
  zonedBucketLabel,
} from "./histogram";
import { useAutoLoad, useViewRows } from "./useViewRows";
import { EmptyState, ErrorState, LoadingCard } from "./ViewState";

export function fetchTimelineHistogram(
  runId: string,
  signal?: AbortSignal,
): Promise<TimelineHistogramPayload> {
  return api<TimelineHistogramPayload>(`/api/runs/${encodeURIComponent(runId)}/timeline-histogram`, {
    signal,
  });
}

const CHART_HEIGHT = 160;

function ShowInColumns() {
  const { patchRoute } = useAppRoute();
  return (
    <button type="button" className="view-link" onClick={() => patchRoute({ view: undefined })}>
      열 보기에서 결과 보기
    </button>
  );
}

// --- timeline ---------------------------------------------------------------

function TimelineHistogram({ runId }: { runId: string }) {
  const queryClient = useQueryClient();
  const queryKey = useMemo(() => ["timeline-histogram", runId] as const, [runId]);
  const [cancelled, setCancelled] = useState(false);
  const histogram = useQuery({
    queryKey,
    queryFn: ({ signal }) => fetchTimelineHistogram(runId, signal),
    enabled: !cancelled,
    staleTime: 60_000,
    retry: false,
  });
  const [choice, setChoice] = useState<GranularityChoice>("auto");
  const { timezone } = useTimezone();
  const [width, setWidth] = useState<number | null>(null);
  const filters = useFilterStore((s) => s.filters);
  const window_ = useMemo(() => timeWindow(filters.from, filters.to), [filters.from, filters.to]);
  // Edges / labels in the display zone, at its offset at the start of the data.
  const anchorDate = useMemo(() => {
    const first = histogram.data?.range_start ? Date.parse(histogram.data.range_start) : Number.NaN;
    return Number.isFinite(first) ? new Date(first) : new Date();
  }, [histogram.data]);
  const offsetMinutes = useMemo(() => tzOffsetMinutes(timezone, anchorDate), [timezone, anchorDate]);
  const zone = zoneLabel(timezone, anchorDate);
  const { buckets, sizeMs, clipped } = useMemo(() => {
    if (!histogram.data) return { buckets: [], sizeMs: 0, clipped: false };
    const serverMs = (histogram.data.bucket_seconds ?? 0) * 1000;
    const forced =
      choice === "hour"
        ? 3_600_000
        : choice === "day"
          ? 86_400_000
          : choice === "native"
            ? serverMs
            : undefined;
    return fitBuckets(histogram.data, {
      maxBars: forced === undefined ? maxBarsFor(width) : Number.MAX_SAFE_INTEGER,
      offsetMinutes,
      fromMs: window_.from,
      untilMs: window_.until,
      ...(forced === undefined ? {} : { sizeMs: forced }),
    });
  }, [histogram.data, choice, width, offsetMinutes, window_]);
  const max = useMemo(() => Math.max(1, ...buckets.map((b) => b.count)), [buckets]);
  const [selection, setSelection] = useState<{ anchor: number; focus: number } | null>(null);
  const [active, setActive] = useState(0);
  const dragging = useRef(false);
  const selectionRef = useRef(selection);
  selectionRef.current = selection;
  const barsRef = useRef<HTMLDivElement | null>(null);
  // Bar count follows the bar area's width (one bar per 4 px).
  // biome-ignore lint/correctness/useExhaustiveDependencies: re-observe once the bars exist
  useEffect(() => {
    const el = barsRef.current;
    if (!el) return;
    const measure = () => setWidth(el.clientWidth || null);
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => observer.disconnect();
  }, [histogram.data]);
  const filterFrom = filters.from ? Date.parse(filters.from) : null;
  const filterTo = filters.to ? Date.parse(filters.to) : null;
  const hasFilter = filterFrom !== null || filterTo !== null;
  // GET /timeline-histogram takes no row conditions: say so instead of implying they shaped the bars.
  const unappliedConditions =
    hasClock(filters) || Boolean(filters.partial) || Boolean(filters.content?.length) || Boolean(filters.geo);

  // biome-ignore lint/correctness/useExhaustiveDependencies: reset when the bars change
  useEffect(() => {
    setSelection(null);
    setActive(0);
  }, [buckets]);

  const apply = (a: number, b: number) => {
    const range = rangeOf(buckets, a, b);
    if (!range) return;
    emitTimeRangeFilter(range.from, range.to);
    const lo = Math.min(a, b);
    const hi = Math.max(a, b);
    const count = buckets.slice(lo, hi + 1).reduce((sum, x) => sum + x.count, 0);
    announce(`시간 범위 필터를 적용했습니다: ${count.toLocaleString("ko-KR")}건`);
  };

  useEffect(() => {
    const finish = () => {
      if (!dragging.current) return;
      dragging.current = false;
      const sel = selectionRef.current;
      if (sel) apply(sel.anchor, sel.focus);
    };
    window.addEventListener("mouseup", finish);
    return () => window.removeEventListener("mouseup", finish);
  });

  const focusBar = (index: number) => {
    const next = Math.min(Math.max(index, 0), buckets.length - 1);
    setActive(next);
    barsRef.current?.querySelector<HTMLElement>(`[data-bar-index="${next}"]`)?.focus();
    return next;
  };

  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const moves: Record<string, number> = {
      ArrowRight: index + 1,
      ArrowLeft: index - 1,
      Home: 0,
      End: buckets.length - 1,
    };
    const target = moves[event.key];
    if (target !== undefined) {
      event.preventDefault();
      const next = focusBar(target);
      if (event.shiftKey) setSelection((sel) => ({ anchor: sel?.anchor ?? index, focus: next }));
      else setSelection(null);
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      const sel = selection ?? { anchor: index, focus: index };
      apply(sel.anchor, sel.focus);
    } else if (event.key === "Escape" && selection) {
      event.preventDefault();
      setSelection(null);
    }
  };

  if (cancelled) {
    return (
      <EmptyState title="히스토그램 불러오기를 취소했습니다.">
        <button type="button" className="view-link" onClick={() => setCancelled(false)}>
          다시 불러오기
        </button>
      </EmptyState>
    );
  }
  if (histogram.isPending) {
    return (
      <LoadingCard
        label="타임라인 히스토그램을 만드는 중…"
        onCancel={() => {
          void queryClient.cancelQueries({ queryKey });
          setCancelled(true);
        }}
      />
    );
  }
  if (histogram.error) {
    return (
      <ErrorState
        message={`히스토그램을 불러오지 못했습니다. ${errorText(histogram.error)}`}
        onRetry={() => void histogram.refetch()}
      />
    );
  }
  const data = histogram.data;
  if (!data || data.parsed_events === 0 || buckets.length === 0) {
    return (
      <EmptyState
        title="플롯할 타임라인 데이터가 없습니다."
        hint={
          data?.unparsed_events
            ? `시각을 해석할 수 없는 이벤트 ${data.unparsed_events.toLocaleString("ko-KR")}건은 제외됩니다. 기간 또는 필터를 조정하세요.`
            : "기간 또는 필터를 조정하세요."
        }
      />
    );
  }

  const lo = selection ? Math.min(selection.anchor, selection.focus) : -1;
  const hi = selection ? Math.max(selection.anchor, selection.focus) : -1;
  const selectedCount = selection ? buckets.slice(lo, hi + 1).reduce((sum, b) => sum + b.count, 0) : 0;
  const tickIndexes = [...new Set([0, Math.floor((buckets.length - 1) / 2), buckets.length - 1])];

  return (
    <div className="view-pane hist-view">
      <div className="view-toolbar">
        <span className="view-count">
          이벤트 {data.parsed_events.toLocaleString("ko-KR")}건
          {data.unparsed_events ? ` · 시각 없음 ${data.unparsed_events.toLocaleString("ko-KR")}건 제외` : ""}
          {` · ${zone}`}
          {clipped ? " · 시간 범위 안만" : ""}
        </span>
        <label className="view-field">
          단위
          <select value={choice} onChange={(event) => setChoice(event.target.value as GranularityChoice)}>
            {(["auto", "hour", "day", "native"] as GranularityChoice[]).map((key) => (
              <option key={key} value={key}>
                {GRANULARITY_LABELS[key]}
                {key === "auto" ? ` (${barSizeLabel(sizeMs)})` : ""}
              </option>
            ))}
          </select>
        </label>
      </div>
      <p className="view-help">
        막대를 누르거나 여러 막대를 끌어 시간 범위 필터를 적용합니다. Shift+화살표로 범위를 넓힙니다.
      </p>
      <div
        ref={barsRef}
        className="hist-bars"
        role="group"
        aria-label={`타임라인 히스토그램, 막대 ${buckets.length}개 (${barSizeLabel(sizeMs)}, ${zone})`}
        style={{ height: CHART_HEIGHT }}
      >
        {buckets.map((bucket, index) => {
          const inFilter =
            hasFilter &&
            (filterFrom === null || bucket.endMs > filterFrom) &&
            (filterTo === null || bucket.startMs <= filterTo);
          const selected = index >= lo && index <= hi;
          const label = zonedBucketAriaLabel(bucket, offsetMinutes, zone);
          return (
            <button
              key={bucket.startMs}
              type="button"
              className="hist-bar"
              data-bar-index={index}
              data-selected={selected || undefined}
              data-in-filter={inFilter || undefined}
              aria-label={label}
              aria-pressed={selected}
              title={label}
              tabIndex={index === active ? 0 : -1}
              onFocus={() => setActive(index)}
              onKeyDown={(event) => onKeyDown(event, index)}
              onMouseDown={(event) => {
                if (event.button !== 0) return;
                dragging.current = true;
                setSelection({ anchor: index, focus: index });
              }}
              onMouseEnter={() => {
                if (dragging.current) setSelection((sel) => (sel ? { ...sel, focus: index } : sel));
              }}
              onMouseUp={() => {
                if (!dragging.current) return;
                dragging.current = false;
                const anchor = selectionRef.current?.anchor ?? index;
                setSelection({ anchor, focus: index });
                apply(anchor, index);
              }}
            >
              <span
                className="hist-bar-fill"
                style={{ height: `${bucket.count ? Math.max(2, (bucket.count / max) * 100) : 0}%` }}
              />
            </button>
          );
        })}
      </div>
      <div className="hist-axis" aria-hidden="true">
        {tickIndexes.map((i) => {
          const bucket = buckets[i];
          return bucket ? (
            <span key={i}>{zonedBucketLabel(bucket.startMs, sizeMs, offsetMinutes)}</span>
          ) : null;
        })}
      </div>
      <div className="hist-status" aria-live="polite">
        {selection ? (
          <span>
            선택: {zonedBucketLabel(buckets[lo]?.startMs ?? 0, sizeMs, offsetMinutes)} ~{" "}
            {zonedBucketLabel(buckets[hi]?.startMs ?? 0, sizeMs, offsetMinutes)} ·{" "}
            {selectedCount.toLocaleString("ko-KR")}건
          </span>
        ) : null}
        {unappliedConditions ? (
          <span className="hist-filter" role="note">
            조건 미적용: 요일·시간대·부분 결과·콘텐츠 유형·위치 조건은 이 막대(타임라인 전체)에 적용되지
            않습니다.
          </span>
        ) : null}
        {hasFilter ? (
          <span className="hist-filter">
            시간 범위 필터 적용 중: {filters.from ?? "처음"} ~ {filters.to ?? "끝"}
            <ShowInColumns />
            <button type="button" className="view-link" onClick={() => emitTimeRangeFilter(null, null)}>
              범위 해제
            </button>
          </span>
        ) : null}
      </div>
    </div>
  );
}

// --- category bars ----------------------------------------------------------

function CategoryBars({ bars, basis }: { bars: CategoryBar[]; basis: string }) {
  const { openCollection } = useAppRoute();
  const filters = useFilterStore((s) => s.filters);
  const listRef = useRef<HTMLDivElement | null>(null);
  const roving = useRovingTabindex(listRef, { orientation: "vertical", itemSelector: "button.hist-cat" });
  const total = bars.reduce((sum, bar) => sum + bar.count, 0);
  const max = Math.max(1, ...bars.map((b) => b.count));

  const activate = (bar: CategoryBar) => {
    if (bar.kind) {
      openCollection("artifacts", { kind: bar.kind });
    } else if (bar.artifactType) {
      const on = toggleTypeFilter(bar.artifactType);
      announce(on ? `유형 필터: ${bar.label}` : "유형 필터를 해제했습니다");
    } else if (bar.extension) {
      const on = toggleExtFilter(bar.extension);
      announce(on ? `확장자 필터: ${bar.label}` : "확장자 필터를 해제했습니다");
    }
  };

  return (
    <div className="view-pane hist-view">
      <div className="view-toolbar">
        <span className="view-count">
          {basis} · 합계 {total.toLocaleString("ko-KR")}건
        </span>
        {filters.types.length || filters.ext.length ? <ShowInColumns /> : null}
      </div>
      <div
        ref={listRef}
        className="hist-cats"
        role="group"
        aria-label="범주별 막대"
        {...roving.containerProps}
      >
        {bars.map((bar, index) => {
          const share = total ? Math.round((bar.count / total) * 1000) / 10 : 0;
          const pressed =
            (bar.artifactType !== undefined && filters.types.includes(bar.artifactType)) ||
            (bar.extension !== undefined && filters.ext.includes(bar.extension));
          const action = bar.kind ? "노드 열기" : bar.artifactType || bar.extension ? "필터" : "";
          return (
            <button
              key={bar.id}
              type="button"
              className="hist-cat"
              aria-label={`${bar.label}: ${bar.count.toLocaleString("ko-KR")}건, ${share}%${action ? `, ${action}` : ""}`}
              aria-pressed={bar.kind ? undefined : pressed}
              disabled={!action}
              {...roving.getItemProps(index)}
              onClick={() => activate(bar)}
            >
              <span className="hist-cat-label">{bar.label}</span>
              <span className="hist-cat-track" aria-hidden="true">
                <span className="hist-cat-fill" style={{ width: `${(bar.count / max) * 100}%` }} />
              </span>
              <span className="hist-cat-count">{bar.count.toLocaleString("ko-KR")}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function ArtifactHistogram({ runId, kind }: { runId: string; kind?: string }) {
  const tree = useQuery({
    queryKey: ["run-tree", runId],
    queryFn: () => getRunTree(runId),
    retry: false,
  });
  const bars = useMemo(() => barsFromTree(tree.data, kind), [tree.data, kind]);
  if (tree.isPending) return <LoadingCard label="아티팩트 건수를 불러오는 중…" />;
  if (tree.error) {
    return (
      <ErrorState
        message={`아티팩트 건수를 불러오지 못했습니다. ${errorText(tree.error)}`}
        onRetry={() => void tree.refetch()}
      />
    );
  }
  if (bars.length === 0) {
    return (
      <EmptyState
        title="막대로 표시할 아티팩트 유형이 없습니다."
        hint="이 노드의 산출물에 유형별 건수가 없습니다. 열 보기에서 행을 확인하세요."
      />
    );
  }
  const categoryBars = (
    <CategoryBars bars={bars} basis={kind ? "아티팩트 유형별 건수" : "아티팩트 종류별 건수"} />
  );
  // The whole-run kind bars can be saved as a baseline and compared (AXIOM E3).
  return kind ? (
    categoryBars
  ) : (
    <BaselineHistogram key={runId} runId={runId}>
      {categoryBars}
    </BaselineHistogram>
  );
}

const ALL_ROWS = (_row: GridRow) => true;
/** Rows read for the files/docs/search bars (the bars say they are a sample). */
export const HISTOGRAM_ROW_LIMIT = 5_000;

function RowHistogram() {
  const route = useRoute();
  const { cq, rows } = useViewRows({ predicate: ALL_ROWS, textFilter: true });
  const capped = useAutoLoad(cq, true, HISTOGRAM_ROW_LIMIT);
  const bars = useMemo(() => barsFromRows(rows, route.collection.id), [rows, route.collection.id]);
  if (cq.error && cq.loadedCount === 0) {
    return <ErrorState message={`행을 불러오지 못했습니다. ${errorText(cq.error)}`} onRetry={cq.refetch} />;
  }
  if (cq.isLoading) return <LoadingCard label="건수를 계산하는 중…" />;
  if (bars.length === 0) {
    return <EmptyState title="막대로 표시할 행이 없습니다." hint="필터를 조정하거나 다른 노드를 여세요." />;
  }
  const what = route.collection.id === "files" ? "확장자별" : "유형별";
  const basis =
    capped || cq.canLoadMore
      ? `${what} 건수 (불러온 행 ${cq.loadedCount.toLocaleString("ko-KR")}개 기준)`
      : `${what} 건수`;
  return <CategoryBars bars={bars} basis={basis} />;
}

export function HistogramView() {
  const route = useRoute();
  if (!route.runId) return <EmptyState title="열린 케이스가 없습니다." />;
  if (route.collection.id === "timeline") return <TimelineHistogram runId={route.runId} />;
  if (route.collection.id === "artifacts")
    return <ArtifactHistogram runId={route.runId} kind={route.collection.kind} />;
  return <RowHistogram />;
}
