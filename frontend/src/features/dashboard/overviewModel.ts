/**
 * 접수 = 사건 개요 (design overhaul F6/F7): pure mapping behind the dashboard's top — the 먼저 할 일
 * list, the key numbers (each with the population it counts) and activity by date from the
 * timeline histogram. Unit-tested without rendering (overview.test.ts).
 */

import type { ReviewCounts, ReviewMapMark } from "../../api/caseDb";
import type { RunProblems } from "../../api/cases";
import type { CanonicalCounts } from "../../api/runs";
import {
  formatTimestamp,
  startOfDayMs,
  type TimezoneChoice,
  wallClockToMs,
  zoneName,
} from "../../utils/time";
import { canRehash, type Seal, unhashableSentence } from "../case/integrity";
import type { TimelineHistogramPayload } from "../views/histogram";

const n = (value: number) => value.toLocaleString("ko-KR");

// --- 먼저 할 일 ---------------------------------------------------------------

export type TodoId = "hash" | "problems" | "indicators" | "report-gap";

export interface TodoItem {
  id: TodoId;
  /** What is wrong, with its count. */
  text: string;
  /** The action button's word. */
  action: string;
  /** Broken evidence integrity: drawn as the error it is. */
  severity: "danger" | "warn" | "info";
}

export interface TodoInput {
  seal: Seal | null;
  /** Run problems (warning + error levels count; notices do not need anyone). */
  problems: RunProblems | undefined;
  /** Indicator candidates of the run (`summary.counts.indicators`). */
  indicators: number | undefined;
  /** Case-DB marks of the run (review-map); undefined while unknown. */
  marks: readonly ReviewMapMark[] | undefined;
  /** The review-map stopped at its limit: mark-based counts are bounds, not exact. */
  marksTruncated?: boolean;
}

/**
 * Problems an examiner has to look at: errors and warnings (notices are informational). Counted by
 * reason group, as the 처리 문제 card lists them (a group's level can differ from its items' levels);
 * `by_level` only when the server sent no groups.
 */
export function problemsNeedingAttention(problems: RunProblems | undefined): number {
  if (!problems) return 0;
  const serious = (level: string) => level === "error" || level === "warning";
  if (problems.groups.length)
    return problems.groups.reduce((sum, group) => (serious(group.level) ? sum + group.count : sum), 0);
  return (problems.by_level.error ?? 0) + (problems.by_level.warning ?? 0);
}

/** A mark that states a verdict (an explicit "unreviewed" / empty status is a cleared mark). */
function isVerdict(mark: ReviewMapMark): boolean {
  return Boolean(mark.status) && mark.status !== "unreviewed" && mark.status !== "cleared";
}

/** Indicator candidates without a verdict: the run's candidates minus the indicator rows marked. */
export function unreviewedIndicators(
  indicators: number | undefined,
  marks: readonly ReviewMapMark[] | undefined,
) {
  if (indicators === undefined || marks === undefined) return undefined;
  const marked = marks.filter((mark) => mark.collection === "indicators" && isVerdict(mark)).length;
  return Math.max(0, indicators - marked);
}

/** 관련 있음 marks not yet included in the report (X4: never included automatically). */
export function relevantNotInReport(marks: readonly ReviewMapMark[] | undefined): number | undefined {
  if (marks === undefined) return undefined;
  return marks.filter((mark) => mark.status === "relevant" && !mark.include_in_report).length;
}

/** Hashable evidence the 먼저 할 일 [검증] / [다시 검증] button hashes: the broken and unverified items. */
export function todoRehashTargets(seal: Seal | null) {
  return seal ? seal.pending.filter(canRehash) : [];
}

/** Only the items that apply, in the order an examiner should take them. */
export function todoItems(input: TodoInput): TodoItem[] {
  const items: TodoItem[] = [];
  const { seal } = input;
  const targets = todoRehashTargets(seal);
  if (seal && seal.kind === "broken") {
    const mismatch = seal.items.filter((item) => item.hash_status === "mismatched").length;
    const failed = seal.counts.broken - mismatch;
    const parts = [
      mismatch ? `기대값 불일치 ${n(mismatch)}건` : "",
      failed ? `계산 실패 ${n(failed)}건` : "",
    ];
    items.push({
      id: "hash",
      text: `증거 무결성이 깨졌습니다: ${parts.filter(Boolean).join(", ")}`,
      action: targets.length ? "다시 검증" : "해시 자세히",
      severity: "danger",
    });
  } else if (seal && seal.kind === "unverified") {
    const files = seal.counts.unverified - seal.unhashable.length;
    const text = [files ? `증거 ${n(files)}건의 해시를 검증하지 않았습니다` : "", unhashableSentence(seal)];
    items.push({
      id: "hash",
      text: text.filter(Boolean).join(" "),
      action: targets.length ? "검증" : "해시 자세히",
      severity: "warn",
    });
  }
  const problems = problemsNeedingAttention(input.problems);
  if (problems > 0) {
    items.push({
      id: "problems",
      text: `처리 문제 ${n(problems)}건 (오류와 경고)을 확인하세요`,
      action: "처리 문제 보기",
      severity: "warn",
    });
  }
  // A truncated review-map misses marks: fewer verdicts seen (unreviewed is an upper bound) and
  // fewer 관련 있음 marks seen (the report gap is a lower bound).
  const truncated = input.marksTruncated === true;
  const indicators = unreviewedIndicators(input.indicators, input.marks);
  if (indicators) {
    items.push({
      id: "indicators",
      text: truncated
        ? `판정하지 않은 지표 후보 최대 ${n(indicators)}건 (판정 목록이 잘려 정확히 세지 못함)`
        : `판정하지 않은 지표 후보 ${n(indicators)}건`,
      action: "지표 후보 열기",
      severity: "info",
    });
  }
  const gap = relevantNotInReport(input.marks);
  if (gap) {
    items.push({
      id: "report-gap",
      text: truncated
        ? `관련 있음 ${n(gap)}건 이상이 보고서에 포함되지 않았습니다 (판정 목록이 잘림)`
        : `관련 있음 ${n(gap)}건이 보고서에 포함되지 않았습니다`,
      action: "검토 보드에서 보기",
      severity: "info",
    });
  }
  return items;
}

/**
 * The empty 먼저 할 일 sentence, naming only what was really checked: a hash still running, no
 * hashable evidence or an unfinished run (no indicator or report counts) is said as such.
 */
export function todoNoneSentence(seal: Seal | null, completed: boolean): string {
  let hash: string;
  if (!seal) hash = "케이스에 연결되지 않아 확인할 증거 해시가 없습니다";
  else if (seal.kind === "na") hash = "해시할 증거가 없습니다";
  else if (seal.kind === "hashing") hash = "해시를 검증하는 중입니다 (끝나면 다시 확인합니다)";
  else if (seal.kind === "computed") hash = "해시는 계산만 됐습니다 (비교할 기대값 없음)";
  else hash = "해시는 마지막 검증 때 기대값과 일치했습니다";
  const checked = completed
    ? "처리 문제, 지표 후보, 보고서 포함을 확인했습니다"
    : "처리 문제를 확인했습니다 (끝까지 처리되지 않아 지표 후보와 보고서 포함은 세지 않았습니다)";
  return `지금 먼저 할 일이 없습니다. ${hash}. ${checked}.`;
}

// --- 사건 숫자 ----------------------------------------------------------------

export type FigureId = "timeline" | "files" | "artifacts" | "indicators" | "marks";

export interface Figure {
  id: FigureId;
  label: string;
  value: number;
  /** The population the number counts (never a bare number). */
  population: string;
}

/** Key numbers of a completed run; `undefined` counts are left out instead of shown as 0. */
export function overviewFigures(
  counts: CanonicalCounts | undefined,
  review: ReviewCounts | undefined,
  scannedFiles?: number,
): Figure[] {
  const figures: Figure[] = [];
  const push = (id: FigureId, label: string, value: number | undefined, population: string) => {
    if (typeof value === "number") figures.push({ id, label, value, population });
  };
  push("timeline", "타임라인 이벤트", counts?.timeline_events, "시각이 있는 이벤트 전체");
  // `counts.files` is the candidate count (category match, known-good hidden), not the scanned files.
  push(
    "files",
    "파일 후보",
    counts?.files,
    typeof scannedFiles === "number"
      ? `처리 모드의 파일 범주에 걸린 후보 (검사한 파일 ${n(scannedFiles)}개 중)`
      : "처리 모드의 파일 범주에 걸린 후보 (검사한 파일 수가 아님)",
  );
  push("artifacts", "아티팩트", counts?.artifacts, "수집기가 해석한 기록 행");
  push("indicators", "지표 후보", counts?.indicators, "자동 탐지된 IOC와 위험 후보");
  if (review) {
    const marks = Object.entries(review.by_status ?? {}).reduce(
      (sum, [status, value]) => (status === "unreviewed" ? sum : sum + value),
      0,
    );
    push("marks", "판정", marks, "이 런에서 판정한 항목");
  }
  return figures;
}

/** True when a completed run collected nothing at all (the numbers would read 0 0 0 0). */
export function isEmptyRun(counts: CanonicalCounts | undefined): boolean {
  if (!counts) return false;
  return !counts.timeline_events && !counts.files && !counts.artifacts && !counts.indicators && !counts.docs;
}

// --- 날짜별 활동 --------------------------------------------------------------

export interface ActivityBar {
  startMs: number;
  /** Exclusive. */
  endMs: number;
  count: number;
  /** "10-22 (목)" for a day, "2026-10" for a month, "10-14 21:00–10-15 03:00" for a server range. */
  label: string;
  /** 0–1 of the busiest bar. */
  ratio: number;
}

export interface Activity {
  /**
   * "range": the server buckets cross display-zone day (or month) boundaries, so they are drawn as
   * they are — a day bar would put events on the wrong date and disagree with the timeline it opens.
   */
  unit: "day" | "month" | "range";
  bars: ActivityBar[];
  total: number;
  busiest: ActivityBar | null;
  /**
   * The busiest display-zone hour inside the busiest day (hours counted from that day's local
   * midnight, so "+05:30" hours start at :00 local). Null when a server bucket spans two local hours.
   */
  busiestHour: { startMs: number; endMs: number; count: number } | null;
}

/** Up to this many days the activity is drawn per day, beyond it per month. */
export const DAY_BARS_UP_TO = 62;
const HOUR = 3_600_000;
const DAY = 86_400_000;

function parseMs(value: string | null | undefined): number | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

/** Next display-zone midnight after `dayStart` (a DST day is 23 or 25 hours long). */
function nextDay(dayStart: number, tz: TimezoneChoice): number {
  return startOfDayMs(dayStart + DAY + 3 * HOUR, tz);
}

function monthStart(ms: number, tz: TimezoneChoice): number {
  const [y, m] = formatTimestamp(new Date(ms), tz, { precision: "date" }).split("-").map(Number) as [
    number,
    number,
  ];
  return wallClockToMs(tz, y, m, 1) ?? startOfDayMs(ms, tz);
}

function nextMonth(start: number, tz: TimezoneChoice): number {
  return monthStart(start + 32 * DAY, tz);
}

function dayLabel(ms: number, tz: TimezoneChoice): string {
  const weekday = new Intl.DateTimeFormat("ko-KR", { weekday: "short", timeZone: zoneName(tz) }).format(
    new Date(ms),
  );
  return `${formatTimestamp(new Date(ms), tz, { precision: "date" }).slice(5)} (${weekday})`;
}

function rangeLabel(startMs: number, endMs: number, tz: TimezoneChoice): string {
  const start = formatTimestamp(new Date(startMs), tz, { precision: "minute" }).slice(5);
  const end = formatTimestamp(new Date(endMs), tz, { precision: "minute" }).slice(5);
  return `${start}–${start.slice(0, 5) === end.slice(0, 5) ? end.slice(6) : end}`;
}

/**
 * Events per display-zone day (per month past 62 days) from `GET …/timeline-histogram`, empty days
 * kept so gaps show; the busiest bar and, inside it, the busiest hour. A server bucket is never
 * split: when one crosses a day (month) boundary of the display zone — 6 h UTC buckets in KST, 7 d
 * buckets at a month end — the server buckets themselves are the bars.
 */
export function activityBars(payload: TimelineHistogramPayload | undefined, tz: TimezoneChoice): Activity {
  const empty: Activity = { unit: "day", bars: [], total: 0, busiest: null, busiestHour: null };
  if (!payload) return empty;
  const events = payload.buckets
    .map((bucket) => ({ at: parseMs(bucket.start), end: parseMs(bucket.end), count: bucket.count }))
    .filter(
      (b): b is { at: number; end: number; count: number } => b.at !== null && b.end !== null && b.count > 0,
    );
  const first = events[0];
  const last = events.at(-1);
  if (!first || !last) return empty;
  const firstDay = startOfDayMs(first.at, tz);
  const spanDays = (last.at - firstDay) / DAY;
  const unit = spanDays < DAY_BARS_UP_TO ? "day" : "month";
  const begin = unit === "day" ? firstDay : monthStart(first.at, tz);
  const step = (at: number) => (unit === "day" ? nextDay(at, tz) : nextMonth(at, tz));
  const bars: ActivityBar[] = [];
  for (let at = begin; at <= last.at; at = step(at)) {
    bars.push({
      startMs: at,
      endMs: step(at),
      count: 0,
      label:
        unit === "day"
          ? dayLabel(at, tz)
          : formatTimestamp(new Date(at), tz, { precision: "date" }).slice(0, 7),
      ratio: 0,
    });
  }
  let index = 0;
  let crosses = false;
  for (const event of events) {
    while (index < bars.length - 1 && event.at >= (bars[index] as ActivityBar).endMs) index += 1;
    const bar = bars[index] as ActivityBar;
    if (event.end > bar.endMs) crosses = true;
    bar.count += event.count;
  }
  if (crosses) {
    const ranges = payload.buckets
      .map((bucket) => ({ at: parseMs(bucket.start), end: parseMs(bucket.end), count: bucket.count }))
      .filter(
        (b): b is { at: number; end: number; count: number } =>
          b.at !== null && b.end !== null && b.at >= first.at && b.at <= last.at,
      )
      .map((b) => ({
        startMs: b.at,
        endMs: b.end,
        count: b.count,
        label: rangeLabel(b.at, b.end, tz),
        ratio: 0,
      }));
    const top = Math.max(0, ...ranges.map((bar) => bar.count));
    let busiestRange: ActivityBar | null = null;
    for (const bar of ranges) {
      bar.ratio = top > 0 ? bar.count / top : 0;
      if (!busiestRange || bar.count > busiestRange.count) busiestRange = bar;
    }
    return {
      unit: "range",
      bars: ranges,
      total: events.reduce((sum, event) => sum + event.count, 0),
      busiest: busiestRange,
      busiestHour: null,
    };
  }
  const max = Math.max(0, ...bars.map((bar) => bar.count));
  let busiest: ActivityBar | null = null;
  for (const bar of bars) {
    bar.ratio = max > 0 ? bar.count / max : 0;
    if (!busiest || bar.count > busiest.count) busiest = bar;
  }
  let busiestHour: Activity["busiestHour"] = null;
  if (busiest && unit === "day" && (payload.bucket_seconds ?? Number.POSITIVE_INFINITY) <= 3600) {
    const hours = new Map<number, number>();
    let fits = true;
    for (const event of events) {
      if (event.at < busiest.startMs || event.at >= busiest.endMs) continue;
      const hour = busiest.startMs + Math.floor((event.at - busiest.startMs) / HOUR) * HOUR;
      if (event.end > hour + HOUR) fits = false;
      hours.set(hour, (hours.get(hour) ?? 0) + event.count);
    }
    for (const [startMs, count] of fits ? hours : []) {
      if (!busiestHour || count > busiestHour.count) busiestHour = { startMs, endMs: startMs + HOUR, count };
    }
  }
  return { unit, bars, total: events.reduce((sum, event) => sum + event.count, 0), busiest, busiestHour };
}
