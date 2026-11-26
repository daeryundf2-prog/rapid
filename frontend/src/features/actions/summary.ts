/** Korean reading of an action-API selection profile (선택 항목 분석 / 관련 항목 표시). Pure. */

import { TIMELINE_SOURCE_LABELS } from "../grid/columns/timeline";
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

export function localTime(iso: string): string {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return iso;
  return new Date(ms).toLocaleString("ko-KR", { dateStyle: "medium", timeStyle: "medium" });
}

export interface FactLine {
  label: string;
  value: string;
}

/** 건수 · 기간 · 출처 · 이벤트 · 자주 나온 경로 · 예시, each only when the profile has it. */
export function summarize(profile: SelectionProfile): FactLine[] {
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
    lines.push({
      label: "기간",
      value: first === last ? localTime(first) : `${localTime(first)} ~ ${localTime(last)}`,
    });
  }
  if (Object.keys(profile.by_source).length) {
    lines.push({
      label: "출처",
      value: counts(profile.by_source, (key) => TIMELINE_SOURCE_LABELS[key] ?? key, 6),
    });
  }
  if (Object.keys(profile.by_event_type).length) {
    lines.push({ label: "이벤트", value: counts(profile.by_event_type, (key) => key, 4) });
  }
  if (profile.top_paths.length) {
    lines.push({
      label: "자주 나온 경로",
      value: profile.top_paths
        .slice(0, 3)
        .map((entry) => `${entry.path} (${n(entry.count)})`)
        .join("\n"),
    });
  }
  const samples = profile.sample.map((row) => row.summary).filter((text): text is string => Boolean(text));
  if (samples.length) lines.push({ label: "예시", value: samples.join("\n") });
  return lines;
}
