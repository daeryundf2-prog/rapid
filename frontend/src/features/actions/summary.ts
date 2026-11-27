/** Korean reading of an action-API selection profile (선택 항목 분석 / 관련 항목 표시). Pure. */

import { formatTimestamp, type TimezoneChoice, zoneShort } from "../../utils/time";
import { eventTypeLabel, TIMELINE_SOURCE_LABELS } from "../grid/columns/timeline";
import type { SelectionProfile } from "./actionApi";

export type StatusChoice = "relevant" | "needs-review" | "excluded" | "unreviewed";

/** The console's review statuses; 재검토 first, the usual next step for related rows. */
export const STATUS_CHOICES: readonly { id: StatusChoice; label: string }[] = [
  { id: "needs-review", label: "재검토" },
  { id: "relevant", label: "관련 있음" },
  { id: "excluded", label: "제외" },
  { id: "unreviewed", label: "미검토로 되돌리기" },
];

const COLLECTION_LABELS: Readonly<Record<string, string>> = {
  timeline: "타임라인",
  files: "파일",
  docs: "문서",
  artifacts: "아티팩트",
  indicators: "지표",
  analysis: "분석 결과",
};

const n = (value: number) => value.toLocaleString("ko-KR");

function counts(record: Record<string, number>, label: (key: string) => string, top: number): string {
  return Object.entries(record)
    .sort((a, b) => b[1] - a[1])
    .slice(0, top)
    .map(([key, count]) => `${label(key) || "(없음)"} ${n(count)}`)
    .join(" · ");
}

/**
 * "2026-10-18 08:02:48 ~ 09:05:05 KST": the selection's span in the display zone, seconds kept,
 * the zone named once (the grid's 시각 reading); the end's date only when it differs.
 */
export function spanText(first: string, last: string, tz: TimezoneChoice): string {
  const a = Date.parse(first);
  const b = Date.parse(last);
  if (Number.isNaN(a) || Number.isNaN(b)) return first === last ? first : `${first} ~ ${last}`;
  const zone = zoneShort(tz, new Date(b));
  const from = formatTimestamp(new Date(a), tz);
  if (a === b) return `${from} ${zone}`;
  const to = formatTimestamp(new Date(b), tz);
  return `${from} ~ ${to.slice(0, 10) === from.slice(0, 10) ? to.slice(11) : to} ${zone}`;
}

export interface FactLine {
  label: string;
  value: string;
  /** 자주 나온 경로: each path on its own line, shown with the console's path display. */
  paths?: readonly { path: string; count: number }[];
}

/** 건수 · 기간 · 출처 · 이벤트 · 자주 나온 경로 · 예시, each only when the profile has it. */
export function summarize(profile: SelectionProfile, tz: TimezoneChoice): FactLine[] {
  const lines: FactLine[] = [];
  const collections = Object.keys(profile.by_collection);
  const total = `${n(profile.total)}건`;
  lines.push({
    label: "건수",
    value:
      collections.length > 1
        ? `${total} (${counts(profile.by_collection, (key) => COLLECTION_LABELS[key] ?? key, 6)})`
        : total,
  });
  if (profile.time_range) {
    const { first, last } = profile.time_range;
    lines.push({ label: "기간", value: spanText(first, last, tz) });
  }
  if (Object.keys(profile.by_source).length) {
    lines.push({
      label: "출처",
      value: counts(profile.by_source, (key) => TIMELINE_SOURCE_LABELS[key] ?? key, 6),
    });
  }
  if (Object.keys(profile.by_event_type).length) {
    // The grid's 이벤트 reading of each raw id (the API counts by `event_type`).
    lines.push({ label: "이벤트", value: counts(profile.by_event_type, eventTypeLabel, 4) });
  }
  if (profile.top_paths.length) {
    const paths = profile.top_paths.slice(0, 3);
    lines.push({
      label: "자주 나온 경로",
      value: paths.map((entry) => `${entry.path} (${n(entry.count)})`).join("\n"),
      paths,
    });
  }
  const samples = profile.sample.map((row) => row.summary).filter((text): text is string => Boolean(text));
  if (samples.length) lines.push({ label: "예시", value: samples.join("\n") });
  return lines;
}
