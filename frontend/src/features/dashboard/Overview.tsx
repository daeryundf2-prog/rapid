/**
 * Top of the 접수 dashboard (design overhaul F6/F7/F9): statuses with their subject, 먼저 할 일,
 * the case's key numbers (each naming what it counts) and activity by date. Data shaping lives
 * in ./overview.ts; this file only renders and routes.
 */

import { useQuery } from "@tanstack/react-query";
import { type ReactNode, useId } from "react";
import type { ReviewCounts } from "../../api/caseDb";
import type { CaseDetail } from "../../api/cases";
import { normalizeRunStatus } from "../../api/runs";
import { CommandButton } from "../../commands/CommandButton";
import { StatusBadge } from "../../components/Badge";
import type { ReviewStatus } from "../../contracts/collection";
import { Icon, type IconName } from "../../icons";
import { useRoute, useTimezone } from "../../state/hooks";
import { formatTimestamp, zoneShort } from "../../utils/time";
import { useRehash } from "../case/IntegritySeal";
import type { Seal } from "../case/integrity";
import { ReasonButton } from "../case/ReasonButton";
import { fetchTimelineHistogram } from "../views/HistogramView";
import { activityBars, type Figure, type TodoItem } from "./overviewModel";
import type { RunDetail } from "./useDashboardData";

const n = (value: number) => value.toLocaleString("ko-KR");

// --- 상태 (F9) -------------------------------------------------------------------

/** "처리 완료", "오류 0", "사건 진행 중": every status names what it is the status of. */
export function DashStatus({ run, caseDetail }: { run: RunDetail; caseDetail: CaseDetail | undefined }) {
  const errors = run.progress?.error_count;
  return (
    <dl className="dash-status" data-testid="dash-status">
      <div>
        <dt>처리</dt>
        <dd>
          <StatusBadge status={String(run.status)} />
        </dd>
      </div>
      {typeof errors === "number" ? (
        <div>
          <dt>처리 오류</dt>
          <dd className="num">{n(errors)}</dd>
        </div>
      ) : null}
      {caseDetail ? (
        <div>
          <dt>사건</dt>
          <dd>{caseDetail.status === "closed" ? "종결" : "진행 중"}</dd>
        </div>
      ) : null}
    </dl>
  );
}

// --- 먼저 할 일 (F7) -------------------------------------------------------------

const TODO_ICON: Record<TodoItem["severity"], IconName> = { danger: "error", warn: "alert", info: "flag" };

export function TodoList({
  items,
  ready,
  waiting,
  seal,
  caseId,
  onAction,
}: {
  items: TodoItem[];
  /** Every input is known: an empty list really means nothing to do. */
  ready: boolean;
  /** The run is still processing (counts come later). */
  waiting: boolean;
  seal: Seal | null;
  caseId: string | null;
  onAction: (item: TodoItem) => void;
}) {
  const headingId = useId();
  const rehash = useRehash(caseId ?? "");
  const act = (item: TodoItem) => {
    if (item.id === "hash" && caseId && seal?.rehashable.length) rehash.mutate(seal.rehashable);
    else onAction(item);
  };
  return (
    <section className="dash-todo" aria-labelledby={headingId} data-testid="dash-todo">
      <h2 id={headingId}>먼저 할 일</h2>
      {items.length ? (
        <ul className="dash-todo-list">
          {items.map((item) => (
            <li key={item.id} className="dash-todo-item" data-severity={item.severity}>
              <Icon name={TODO_ICON[item.severity]} size={16} className="dash-todo-icon" />
              <span className="dash-todo-text">{item.text}</span>
              <ReasonButton
                className="button"
                reason={item.id === "hash" && rehash.isPending ? "요청 중입니다" : undefined}
                onClick={() => act(item)}
              >
                {item.action}
              </ReasonButton>
            </li>
          ))}
        </ul>
      ) : null}
      {waiting ? (
        <p className="dash-note">처리가 끝나면 처리 문제, 지표 후보, 판정을 세어 할 일을 보여 줍니다.</p>
      ) : !items.length ? (
        <p className="dash-todo-none">
          {ready
            ? "지금 먼저 할 일이 없습니다. 해시, 처리 문제, 지표 후보, 보고서 포함을 모두 확인했습니다."
            : "할 일을 확인하는 중입니다…"}
        </p>
      ) : null}
    </section>
  );
}

// --- 사건 개요 (F6) --------------------------------------------------------------

const MARK_ROWS: ReadonlyArray<{ status: ReviewStatus; label: string }> = [
  { status: "relevant", label: "관련 있음" },
  { status: "needs-review", label: "재검토" },
  { status: "excluded", label: "제외" },
];

export function OverviewFigures({
  run,
  figures,
  empty,
  review,
  error,
  onOpen,
  onShowProblems,
}: {
  run: RunDetail;
  figures: Figure[];
  /** Completed but nothing collected. */
  empty: boolean;
  review: ReviewCounts | undefined;
  error: string | null;
  onOpen: (figure: Figure["id"], status?: ReviewStatus) => void;
  onShowProblems: () => void;
}) {
  const headingId = useId();
  const { openCollection } = useRoute();
  const status = normalizeRunStatus(run.status);
  const failed = status === "failed" || status === "cancelled" || status === "interrupted";
  const active = status === "queued" || status === "running";
  let body: ReactNode;
  if (failed) {
    const reason = run.progress?.error?.message || run.error;
    body = (
      <div className="dash-state" data-testid="overview-failed">
        <p className="dash-state-title">
          {status === "failed"
            ? "처리가 실패했습니다"
            : status === "cancelled"
              ? "처리를 취소했습니다"
              : "처리가 중단되었습니다"}
        </p>
        <p className="dash-note">
          {reason ? `${reason} ` : ""}끝까지 처리되지 않아 사건 숫자를 세지 않습니다.
        </p>
        <div className="dash-row">
          <CommandButton command="case.retry" label="다시 실행" variant="primary" showReason />
          <button type="button" className="button" onClick={() => openCollection("process")}>
            처리 단계 보기
          </button>
        </div>
      </div>
    );
  } else if (active) {
    body = (
      <p className="dash-note" data-testid="overview-waiting">
        처리 중입니다. 끝나면 사건 숫자가 채워집니다.
      </p>
    );
  } else if (error) {
    body = <p className="error-banner">사건 숫자를 불러오지 못했습니다: {error}</p>;
  } else if (empty) {
    body = (
      <div className="dash-state" data-testid="overview-empty">
        <p className="dash-state-title">이 런에서 수집된 항목이 없습니다</p>
        <p className="dash-note">
          타임라인, 파일 후보, 아티팩트, 지표 후보가 모두 0건입니다. 처리 문제와 처리 설정의 수집 계열을
          확인하세요.
        </p>
        <div className="dash-row">
          <button type="button" className="button" onClick={onShowProblems}>
            처리 문제 보기
          </button>
          <CommandButton command="case.run.add" label="다른 설정으로 런 추가" showReason />
        </div>
      </div>
    );
  } else if (!figures.length) {
    body = <p className="dash-note">사건 숫자를 불러오는 중입니다…</p>;
  } else {
    body = (
      <ul className="dash-figures">
        {figures.map((figure) =>
          figure.id === "marks" ? (
            <li key={figure.id} className="dash-figure is-marks">
              <span className="dash-figure-value">{n(figure.value)}</span>
              <span className="dash-figure-label">{figure.label}</span>
              <span className="dash-figure-pop">{figure.population}</span>
              <ul className="dash-figure-breakdown" aria-label="판정 내역">
                {MARK_ROWS.map((row) => (
                  <li key={row.status}>
                    <button
                      type="button"
                      className="dash-link"
                      onClick={() => onOpen("marks", row.status)}
                      aria-label={`${row.label} ${n(review?.by_status?.[row.status] ?? 0)}건 검토 보드에서 열기`}
                    >
                      {row.label} <span className="num">{n(review?.by_status?.[row.status] ?? 0)}</span>
                    </button>
                  </li>
                ))}
                <li>
                  <button
                    type="button"
                    className="dash-link"
                    onClick={() => onOpen("marks", "include-in-report")}
                    aria-label={`보고서 포함 ${n(review?.report_candidates ?? 0)}건 검토 보드에서 열기`}
                  >
                    보고서 포함 <span className="num">{n(review?.report_candidates ?? 0)}</span>
                  </button>
                </li>
              </ul>
            </li>
          ) : (
            <li key={figure.id}>
              <button
                type="button"
                className="dash-figure"
                onClick={() => onOpen(figure.id)}
                aria-label={`${figure.label} ${n(figure.value)}건 (${figure.population}) 열기`}
              >
                <span className="dash-figure-value">{n(figure.value)}</span>
                <span className="dash-figure-label">{figure.label}</span>
                <span className="dash-figure-pop">{figure.population}</span>
              </button>
            </li>
          ),
        )}
      </ul>
    );
  }
  return (
    <section className="dash-overview" aria-labelledby={headingId} data-testid="dash-overview">
      <h2 id={headingId}>사건 개요</h2>
      {body}
    </section>
  );
}

// --- 날짜별 활동 (F6) ------------------------------------------------------------

/** Bars past this count scroll inside the section. */
const ACTIVITY_SCROLL_FROM = 14;

export function ActivityByDate({
  runId,
  completed,
  events,
}: {
  runId: string;
  completed: boolean;
  /** The run's timeline event count (summary); 0 = nothing to draw, undefined = unknown yet. */
  events: number | undefined;
}) {
  const enabled = completed && Boolean(events);
  const headingId = useId();
  const { route, navigate } = useRoute();
  const { timezone } = useTimezone();
  // Same key as the histogram view: one request serves both.
  const histogram = useQuery({
    queryKey: ["timeline-histogram", runId],
    queryFn: ({ signal }) => fetchTimelineHistogram(runId, signal),
    enabled,
    staleTime: 60_000,
    retry: false,
  });
  const activity = activityBars(histogram.data, timezone);
  const zone = zoneShort(timezone, new Date(activity.busiest?.startMs ?? Date.now()));
  const openRange = (fromMs: number, toMs: number) =>
    navigate({
      runId,
      collection: "timeline",
      from: new Date(fromMs).toISOString(),
      to: new Date(toMs - 1).toISOString(),
      ...(route.tz ? { tz: route.tz } : {}),
    });
  const clock = (ms: number) => formatTimestamp(new Date(ms), timezone, { precision: "minute" }).slice(11);

  let body: ReactNode;
  if (!completed) body = <p className="dash-note">처리가 끝나면 날짜별 이벤트 수를 보여 줍니다.</p>;
  else if (events === 0) body = <p className="dash-note">시각이 있는 이벤트가 없습니다.</p>;
  else if (events === undefined) body = <p className="dash-note">날짜별 활동을 불러오는 중입니다…</p>;
  else if (histogram.isPending) body = <p className="dash-note">날짜별 활동을 불러오는 중입니다…</p>;
  else if (histogram.isError)
    body = <p className="error-banner">날짜별 활동을 불러오지 못했습니다: {histogram.error.message}</p>;
  else if (!activity.busiest) body = <p className="dash-note">시각이 있는 이벤트가 없습니다.</p>;
  else {
    const busiest = activity.busiest;
    const share = activity.total ? Math.round((busiest.count / activity.total) * 100) : 0;
    const unitWord = activity.unit === "day" ? "날" : "달";
    body = (
      <>
        <div className="dash-activity-lead">
          <p>
            가장 붐빈 {unitWord}은 <strong>{busiest.label}</strong>로 {n(busiest.count)}건입니다 (전체{" "}
            {n(activity.total)}건의 {share}%).
            {activity.busiestHour
              ? ` 그날 가장 많은 시간은 ${clock(activity.busiestHour.startMs)}~${clock(activity.busiestHour.endMs - 60_000)} (${n(activity.busiestHour.count)}건)입니다.`
              : ""}
          </p>
          <button type="button" className="button" onClick={() => openRange(busiest.startMs, busiest.endMs)}>
            이 {unitWord} 타임라인 열기
          </button>
        </div>
        <ol
          className={`dash-days${activity.bars.length > ACTIVITY_SCROLL_FROM ? " is-scroll" : ""}`}
          aria-label={`${activity.unit === "day" ? "날짜별" : "달별"} 이벤트 수 (${zone})`}
        >
          {activity.bars.map((bar) => (
            <li key={bar.startMs}>
              <button
                type="button"
                className="dash-day"
                data-busiest={bar === busiest ? "true" : undefined}
                onClick={() => openRange(bar.startMs, bar.endMs)}
                aria-label={`${bar.label} ${n(bar.count)}건, 타임라인 열기`}
              >
                <span className="dash-day-label">{bar.label}</span>
                <span className="dash-day-track" aria-hidden="true">
                  <span
                    className="dash-day-fill"
                    style={{ inlineSize: `${bar.count ? Math.max(2, bar.ratio * 100) : 0}%` }}
                  />
                </span>
                <span className="dash-day-count">{n(bar.count)}</span>
              </button>
            </li>
          ))}
        </ol>
      </>
    );
  }
  return (
    <section className="dash-activity" aria-labelledby={headingId} data-testid="dash-activity">
      <h2 id={headingId}>
        날짜별 활동 <span className="dash-section-meta">{zone} 기준</span>
      </h2>
      {body}
    </section>
  );
}
