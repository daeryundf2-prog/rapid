// biome-ignore-all lint/a11y/useSemanticElements: grouped toggle buttons inside a fieldset section use role="group" divs like the rest of the condition panel
/**
 * Condition panel sections of r4 §2.3 (V3 필터): 사건 시각 ± n시간, 요일 · 시간대 · 업무 외 시간
 * (in the display timezone), 부분 결과 and the global 콘텐츠 유형 chips. Every control writes the
 * filter store (the URL), so the chips, saved condition sets and links carry them; the listing
 * applies them on the server where it can (artifacts · files · timeline).
 */

import { useEffect, useId, useMemo, useState } from "react";
import { useTimezone } from "../../state/hooks";
import { useAppStore } from "../../state/store";
import { zoneLabel } from "../../utils/time";
import { useAnalysisStore } from "../analysis/store";
import { WEEKDAY_IDS } from "./conditionValues";
import { CONTENT_TYPE_IDS, CONTENT_TYPES } from "./contentTypes";
import { toLocalInput } from "./filterModel";
import { useFilterStore } from "./filterStore";
import {
  DEFAULT_OFFHOURS,
  hoursAfterPick,
  incidentFromAnalyses,
  incidentRange,
  parseHours,
  WEEKDAY_LABELS,
} from "./rowConditions";

export const INCIDENT_SPANS: readonly number[] = [1, 3, 6, 12, 24, 72];
const HOUR_CHOICES = Array.from({ length: 24 }, (_, hour) => hour);

function toggle(list: readonly string[], value: string): string[] {
  return list.includes(value) ? list.filter((item) => item !== value) : [...list, value];
}

/** 사건 시각 ± n시간 → from/to. The incident time comes from the newest 특이사항 analysis when set. */
export function IncidentRange() {
  const runId = useAppStore((s) => s.route.runId);
  const patch = useFilterStore((s) => s.patchFilters);
  // The analysis jobs the shell already polls (status-bar chip / tree): no request of our own.
  const analyses = useAnalysisStore((s) => (s.runId === runId ? s.analyses : null));
  const incident = useMemo(() => incidentFromAnalyses(analyses ?? []), [analyses]);
  const [at, setAt] = useState("");
  const [fromIncident, setFromIncident] = useState(false);
  const [span, setSpan] = useState(6);
  const atId = useId();
  const spanId = useId();
  // Prefill from the run's incident time once it is known (the examiner can still edit it).
  useEffect(() => {
    if (!incident) return;
    setAt((current) => {
      if (current) return current;
      setFromIncident(true);
      return toLocalInput(incident.start);
    });
  }, [incident]);
  // An unedited prefill keeps the analysis' whole incident window (start … end) ± n hours.
  const range = at ? incidentRange(at, span, fromIncident ? (incident?.end ?? undefined) : undefined) : null;
  return (
    <div className="filter-incident" role="group" aria-label="사건 시각 기준 범위">
      <span className="filter-range-label">사건 시각 ±</span>
      <label className="sr-only" htmlFor={atId}>
        사건 시각
      </label>
      <input
        id={atId}
        type="datetime-local"
        value={at}
        title={incident ? "특이사항 분석에 지정된 사건 시각" : "사건 시각을 입력하세요"}
        onChange={(event) => {
          setAt(event.target.value);
          setFromIncident(false);
        }}
      />
      <label className="sr-only" htmlFor={spanId}>
        앞뒤 시간
      </label>
      <select id={spanId} value={span} onChange={(event) => setSpan(Number(event.target.value))}>
        {INCIDENT_SPANS.map((hours) => (
          <option key={hours} value={hours}>
            {`± ${hours}시간`}
          </option>
        ))}
      </select>
      <button
        type="button"
        className="grid-btn grid-btn-quiet"
        disabled={!range}
        aria-label={range ? `사건 시각 ±${span}시간 적용` : "사건 시각을 먼저 입력하세요"}
        onClick={() => range && patch(range)}
      >
        적용
      </button>
      {fromIncident && incident?.end ? (
        <span className="filter-empty">특이사항 분석의 사건 구간(시작~종료) ± n시간</span>
      ) : null}
    </div>
  );
}

/** 요일 · 시간대 · 업무 외 시간. */
export function ClockSection() {
  const filters = useFilterStore((s) => s.filters);
  const patch = useFilterStore((s) => s.patchFilters);
  const { timezone } = useTimezone();
  const weekdays = filters.weekdays ?? [];
  const window = parseHours(filters.hours);
  const [start, end] =
    window ?? (filters.offhours ? (parseHours(DEFAULT_OFFHOURS) as [number, number]) : [9, 18]);
  // A pick that would empty the window moves the other bound (hoursAfterPick); it never clears it.
  const pickHour = (bound: "start" | "end", hour: number) =>
    patch({ hours: hoursAfterPick([start, end], bound, hour) });
  const startId = useId();
  const endId = useId();
  return (
    <fieldset className="popover-section" aria-label="요일·시간대">
      <legend className="popover-title">요일·시간대</legend>
      <label className="filter-type-option">
        <input
          type="checkbox"
          checked={Boolean(filters.offhours)}
          onChange={(event) => patch({ offhours: event.target.checked || undefined })}
        />
        <span className="filter-type-text">
          <span className="filter-type-label">업무 외 시간</span>
          <span className="filter-type-id">시간대 또는 요일 중 하나라도 맞으면 (기본 18–09시·토·일)</span>
        </span>
      </label>
      <div className="segmented filter-weekdays" role="group" aria-label="요일">
        {WEEKDAY_IDS.map((day) => (
          <button
            key={day}
            type="button"
            aria-pressed={weekdays.includes(day)}
            aria-label={`${WEEKDAY_LABELS[day]}요일`}
            onClick={() => {
              const next = toggle(weekdays, day);
              patch({ weekdays: next.length ? WEEKDAY_IDS.filter((id) => next.includes(id)) : undefined });
            }}
          >
            {WEEKDAY_LABELS[day]}
          </button>
        ))}
      </div>
      <div className="filter-hours">
        <label htmlFor={startId} className="filter-range-label">
          시간대
        </label>
        <select
          id={startId}
          aria-label="시작 시"
          value={window ? start : ""}
          onChange={(event) =>
            event.target.value === ""
              ? patch({ hours: undefined })
              : pickHour("start", Number(event.target.value))
          }
        >
          <option value="">{filters.offhours ? "기본(18시)" : "전체"}</option>
          {HOUR_CHOICES.map((hour) => (
            <option key={hour} value={hour}>{`${hour}시`}</option>
          ))}
        </select>
        <span aria-hidden="true">–</span>
        <label htmlFor={endId} className="sr-only">
          끝 시
        </label>
        <select
          id={endId}
          aria-label="끝 시 (이 시각 전까지)"
          value={window ? end : ""}
          onChange={(event) =>
            event.target.value === ""
              ? patch({ hours: undefined })
              : pickHour("end", Number(event.target.value))
          }
        >
          <option value="">{filters.offhours ? "기본(09시)" : "전체"}</option>
          {HOUR_CHOICES.map((hour) => (
            <option key={hour} value={hour}>{`${hour}시`}</option>
          ))}
        </select>
      </div>
      <p className="filter-empty">{`표시 시간대(${zoneLabel(timezone)}) 기준 · 끝 시각 전까지 · 자정을 넘을 수 있음(예: 18–09시)`}</p>
    </fieldset>
  );
}

/** 부분 결과 + 콘텐츠 유형 (global chips, files and artifacts alike). */
export function ResultSection() {
  const filters = useFilterStore((s) => s.filters);
  const patch = useFilterStore((s) => s.patchFilters);
  const content = filters.content ?? [];
  return (
    <fieldset className="popover-section" aria-label="콘텐츠 유형·부분 결과">
      <legend className="popover-title">콘텐츠 유형</legend>
      <div className="filter-content-chips" role="group" aria-label="콘텐츠 유형">
        {CONTENT_TYPE_IDS.map((id) => (
          <button
            key={id}
            type="button"
            className="filter-content-chip"
            aria-pressed={content.includes(id)}
            onClick={() => {
              const next = toggle(content, id);
              patch({
                content: next.length ? CONTENT_TYPE_IDS.filter((item) => next.includes(item)) : undefined,
              });
            }}
          >
            {CONTENT_TYPES[id].label}
          </button>
        ))}
      </div>
      <label className="filter-type-option">
        <input
          type="checkbox"
          checked={Boolean(filters.partial)}
          onChange={(event) => patch({ partial: event.target.checked || undefined })}
        />
        <span className="filter-type-text">
          <span className="filter-type-label">부분 결과만</span>
          <span className="filter-type-id">파서 오류·잘림·복호 실패·부분 범위 행</span>
        </span>
      </label>
    </fieldset>
  );
}
