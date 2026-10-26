/**
 * 접수 dashboard cards (plan §9 X1; r7 examiner-first redesign). Each card receives its query
 * results and a navigation callback; data shaping lives in ./model.ts and ./disclosures.ts.
 * The case-side cards (사건 정보 · 증거 · 처리 경고·제한 사항 · 노트·메모) live in ./caseCards.tsx.
 */

import { useQueries } from "@tanstack/react-query";
import { type ReactNode, useEffect } from "react";
import { announce } from "../../a11y";
import { downloadFile } from "../../api/client";
import { type ExportEntry, getKeywordHitCount } from "../../api/dashboard";
import type { CanonicalCounts, ItemRow, RunWarning } from "../../api/runs";
import { RUN_MODE_LABEL, runDisplayName } from "../../app/collections";
import { StatusBadge } from "../../components/Badge";
import { ToneChip } from "../../components/ToneChip";
import type { ReviewStatus } from "../../contracts/collection";
import { Icon } from "../../icons";
import { kindLabel } from "../derived/tables";
import { CardEmpty } from "./Card";
import { type DisclosureItem, isNotice, stepLabelKo } from "./disclosures";
import {
  type CategoryBar,
  exportTypeLabel,
  formatDuration,
  formatTime,
  type KeywordRow,
  type ReviewSummaryRow,
  type StageRow,
} from "./model";
import type { ProviderProgress, RunDetail } from "./useDashboardData";

const n = (value: number) => value.toLocaleString("ko-KR");

function ms(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

// --- 상태 줄 (sticky dashboard head) -------------------------------------------------

/** 시작 / 완료 / 총 소요 / 단계 진행 of a run, shared by the status strip and the 처리 상태 card. */
export function runTiming(run: RunDetail, stages: StageRow[], now = Date.now()) {
  const progress = run.progress ?? null;
  const completed = run.status === "completed";
  const startedAt = progress?.started_at ?? run.created_at ?? null;
  const completedAt = completed ? (progress?.completed_at ?? run.updated_at ?? null) : null;
  const start = ms(startedAt);
  const end = completedAt ? ms(completedAt) : run.status === "running" ? now : null;
  const done = stages.filter((stage) => stage.state === "done").length;
  return {
    startedAt,
    completedAt,
    totalMs: start !== null && end !== null ? Math.max(0, end - start) : null,
    stagesDone: done,
    stagesTotal: stages.length,
  };
}

/**
 * The sticky status strip of the 접수 dashboard: run name · 상태 · 모드 · 시작→완료 · 총 소요 ·
 * 단계 N/N 완료 (bar) · 처리 요약 보기 · 처리 설정 보기. The raw run id is not printed: it is the
 * name's tooltip and the 런 ID 복사 action.
 */
export function StatusStrip({
  run,
  stages,
  crumb,
  onOpenSummary,
  onOpenSettings,
  children,
}: {
  run: RunDetail;
  stages: StageRow[];
  crumb: string | null;
  onOpenSummary: () => void;
  onOpenSettings: () => void;
  children?: ReactNode;
}) {
  const completed = run.status === "completed";
  const timing = runTiming(run, stages);
  const mode = run.request?.mode ?? "";
  const percent = timing.stagesTotal ? Math.round((timing.stagesDone / timing.stagesTotal) * 100) : 0;
  const copyId = () => {
    const write = navigator.clipboard?.writeText?.(run.run_id);
    Promise.resolve(write)
      .then(() => announce("런 ID를 복사했습니다"))
      .catch(() => announce("런 ID를 복사하지 못했습니다", { politeness: "assertive" }));
  };
  return (
    <div className="dash-strip" data-testid="dash-strip">
      <div className="dash-strip-title">
        <h1 title={`런 ID ${run.run_id}`}>{runDisplayName(run)}</h1>
        <StatusBadge status={String(run.status)} />
        {mode ? <span className="dash-strip-mode">{RUN_MODE_LABEL[mode] ?? mode}</span> : null}
        <button
          type="button"
          className="button ghost icon-only"
          aria-label="런 ID 복사"
          title={`런 ID 복사 (${run.run_id})`}
          onClick={copyId}
        >
          <Icon name="copy" />
        </button>
        {crumb ? (
          <p className="dash-crumb" data-testid="case-crumb">
            <span className="visually-hidden">케이스 › 증거: </span>
            {crumb}
          </p>
        ) : null}
      </div>
      <dl className="dash-strip-facts">
        <div>
          <dt>시작→완료</dt>
          <dd>
            {formatTime(timing.startedAt)} → {timing.completedAt ? formatTime(timing.completedAt) : "—"}
          </dd>
        </div>
        <div>
          <dt>총 소요</dt>
          <dd>{formatDuration(timing.totalMs)}</dd>
        </div>
        <div className="dash-strip-progress">
          <dt className="visually-hidden">단계 진행</dt>
          <dd>
            <span
              className="dash-progress"
              role="progressbar"
              aria-label="처리 단계 진행"
              aria-valuemin={0}
              aria-valuemax={timing.stagesTotal || 1}
              aria-valuenow={timing.stagesDone}
              aria-valuetext={`단계 ${timing.stagesDone}/${timing.stagesTotal} 완료`}
            >
              <span className="dash-progress-fill" style={{ inlineSize: `${percent}%` }} />
            </span>
            <span>
              단계 {timing.stagesDone}/{timing.stagesTotal} 완료
            </span>
          </dd>
        </div>
      </dl>
      <div className="dash-strip-actions">
        <button
          type="button"
          className="button"
          onClick={onOpenSummary}
          aria-disabled={completed ? undefined : true}
          title={completed ? undefined : "런이 완료되면 처리 요약을 볼 수 있습니다"}
        >
          <Icon name="report" /> 처리 요약 보기
        </button>
        <button type="button" className="button ghost" onClick={onOpenSettings}>
          <Icon name="settings" /> 처리 설정 보기
        </button>
        {children}
      </div>
    </div>
  );
}

// --- 처리 상태 -------------------------------------------------------------------

const PROVIDER_STATUS: Record<string, string> = {
  queued: "대기",
  running: "실행 중",
  completed: "완료",
  error: "오류",
  reused: "재사용",
};

const COUNT_TILES: Array<{ key: keyof CanonicalCounts; label: string }> = [
  { key: "files", label: "파일" },
  { key: "artifacts", label: "아티팩트" },
  { key: "docs", label: "문서" },
  { key: "timeline_events", label: "타임라인 이벤트" },
  { key: "indicators", label: "지표 후보" },
];

/**
 * 처리 상태 (formerly 케이스 처리 세부): what the run produced (건수), where it went (출력 폴더) and,
 * under one collapsed "단계 상세", the stage table · 수집기 table · 검증 이슈. 상태 · 모드 · 시각 are in
 * the status strip above, 증거 경로 in the 증거 card.
 */
export function StatusCard({
  run,
  stages,
  counts,
  outputDir,
  issues,
}: {
  run: RunDetail;
  stages: StageRow[];
  counts: CanonicalCounts | undefined;
  outputDir: string;
  issues: ItemRow[] | undefined;
}) {
  const progress = run.progress ?? null;
  const providers = Object.entries(progress?.providers ?? {}).sort(([a], [b]) => a.localeCompare(b)) as Array<
    [string, ProviderProgress]
  >;
  const running = stages.find((stage) => stage.state === "running");
  const providerDone =
    progress?.completed_count ?? providers.filter(([, p]) => p.status === "completed").length;
  const providerTotal = progress?.total_count ?? providers.length;
  const summaryParts = [
    `단계 ${stages.filter((s) => s.state === "done").length}/${stages.length}`,
    providers.length ? `수집기 ${providerDone}/${providerTotal} · 오류 ${progress?.error_count ?? 0}` : "",
    issues?.length ? `검증 이슈 ${n(issues.length)}건` : "",
  ].filter(Boolean);
  return (
    <div className="dash-status" data-testid="status-card">
      {run.error ? <p className="error-banner">{run.error}</p> : null}
      {progress?.error ? (
        <p className="error-banner">
          {stepLabelKo(String(progress.error.stage ?? ""))} 단계 오류: {progress.error.message}
        </p>
      ) : null}
      {running ? (
        <p className="dash-status-now">
          현재 단계: <b title={running.stage}>{stepLabelKo(running.stage)}</b>{" "}
          <span className="badge info">진행 중</span> · {formatDuration(running.durationMs)}
        </p>
      ) : null}
      {counts ? (
        <ul className="dash-tiles" aria-label="처리 결과 건수">
          {COUNT_TILES.map((tile) => (
            <li key={tile.key}>
              <span className="dash-tile-value">{n(Number(counts[tile.key] ?? 0))}</span>
              <span className="dash-tile-label">{tile.label}</span>
            </li>
          ))}
        </ul>
      ) : run.status === "completed" ? null : (
        <p className="dash-note">처리 결과 건수는 런이 완료되면 표시됩니다.</p>
      )}
      {outputDir ? (
        <dl className="detail-grid dash-facts">
          <dt>출력 폴더</dt>
          <dd className="mono dash-wrap">{outputDir}</dd>
        </dl>
      ) : null}
      {stages.length || providers.length || issues?.length ? (
        <details className="dash-details" data-testid="stage-details">
          <summary>단계 상세 — {summaryParts.join(" · ")}</summary>
          {stages.length ? (
            <div className="dash-scroll">
              <table className="data-table dash-table" aria-label="처리 단계">
                <thead>
                  <tr>
                    <th scope="col">단계</th>
                    <th scope="col">상태</th>
                    <th scope="col">소요</th>
                  </tr>
                </thead>
                <tbody>
                  {stages.map((stage, index) => (
                    // biome-ignore lint/suspicious/noArrayIndexKey: stage names can repeat across resumes
                    <tr key={`${stage.stage}-${index}`}>
                      <td title={stage.stage}>{stepLabelKo(stage.stage)}</td>
                      <td>
                        <span className={`badge ${stage.state === "done" ? "ok" : "info"}`}>
                          {stage.state === "done" ? "완료" : "진행 중"}
                        </span>
                      </td>
                      <td>{formatDuration(stage.durationMs)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="dash-note">진행 기록이 없습니다 (가져온 런이거나 진행 파일이 없는 런입니다).</p>
          )}
          {providers.length ? (
            <div className="dash-scroll">
              <table className="data-table dash-table" aria-label="수집기 진행">
                <thead>
                  <tr>
                    <th scope="col">수집기</th>
                    <th scope="col">상태</th>
                    <th scope="col">소요</th>
                    <th scope="col" className="num">
                      건수
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {providers.map(([kind, p]) => (
                    <tr key={kind}>
                      <td className="dash-wrap" title={kind}>
                        {kindLabel(kind)}
                      </td>
                      <td>{PROVIDER_STATUS[p.status ?? ""] ?? p.status ?? "—"}</td>
                      <td>{formatDuration(p.duration_ms)}</td>
                      <td className="num">
                        {typeof p.artifact_count === "number" ? n(p.artifact_count) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          {issues?.length ? (
            <>
              <p className="dash-subhead">검증 이슈 {n(issues.length)}건</p>
              <ul className="dash-issues" aria-label="검증 이슈">
                {issues.slice(0, 100).map((issue, index) => (
                  // biome-ignore lint/suspicious/noArrayIndexKey: static read-only list
                  <li key={index}>
                    <span className="dash-issue-step" title={String(issue.step ?? "")}>
                      {issue.step ? stepLabelKo(String(issue.step)) : ""}
                    </span>{" "}
                    {String(issue.message ?? "")}
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </details>
      ) : (
        <p className="dash-note">진행 기록이 없습니다 (가져온 런이거나 진행 파일이 없는 런입니다).</p>
      )}
    </div>
  );
}

// --- 아티팩트 범주 -----------------------------------------------------------

export function CategoryCard({
  bars,
  total,
  onOpenCategory,
}: {
  bars: CategoryBar[];
  total: number;
  onOpenCategory: (category: string) => void;
}) {
  if (bars.length === 0) {
    return (
      <CardEmpty title="아티팩트가 없습니다">
        이 런의 수집 모드에서 아티팩트 수집기가 결과를 내지 않았습니다. 파일·문서 노드에서 항목을 확인하세요.
      </CardEmpty>
    );
  }
  return (
    <ul className="dash-bars" aria-label={`아티팩트 범주, 전체 ${n(total)}건`}>
      {bars.map((bar) => (
        <li key={bar.category.id}>
          <button
            type="button"
            className="dash-bar"
            onClick={() => onOpenCategory(bar.category.id)}
            aria-label={`${bar.category.label} ${n(bar.count)}건 열기`}
          >
            <span className="dash-bar-label">
              <Icon name={bar.category.icon} />
              {bar.category.label}
            </span>
            <span className="dash-bar-track" aria-hidden="true">
              <span className="dash-bar-fill" style={{ inlineSize: `${Math.max(2, bar.ratio * 100)}%` }} />
            </span>
            <span className="dash-bar-count">{n(bar.count)}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}

// --- 검토·보고서 (리뷰 상태 + 내보내기 이력) -------------------------------------------

export function ReviewCard({
  rows,
  onOpenStatus,
}: {
  rows: ReviewSummaryRow[];
  onOpenStatus: (status: ReviewStatus | undefined) => void;
}) {
  const empty = rows.every((row) => row.count === 0);
  return (
    <section className="dash-section" aria-label="리뷰 상태">
      <h3 className="dash-subhead">리뷰 상태</h3>
      <div className="dash-scroll">
        <table className="data-table dash-table" aria-label="리뷰 상태별 건수">
          <tbody>
            {rows.map((row) => (
              <tr key={row.key}>
                <td>
                  <button
                    type="button"
                    className="dash-link"
                    onClick={() => onOpenStatus(row.status)}
                    aria-label={`${row.label} ${n(row.count)}건 리뷰보드에서 열기`}
                  >
                    <span className="dash-chip" style={{ background: row.color }} aria-hidden="true" />
                    {row.label}
                  </button>
                </td>
                <td className="num">{n(row.count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {empty ? (
        <CardEmpty title="표시한 항목 없음" compact>
          그리드에서 R·I·X·B로 표시하면 집계됩니다
        </CardEmpty>
      ) : null}
    </section>
  );
}

export function ExportsCard({ entries }: { entries: ExportEntry[] }) {
  return (
    <section className="dash-section" aria-label="내보내기 이력">
      <h3 className="dash-subhead">
        내보내기 이력
        {entries.length ? <span className="dash-note"> · 이력 {n(entries.length)}건</span> : null}
      </h3>
      {entries.length === 0 ? (
        <CardEmpty title="내보낸 보고서·추출 파일 없음" compact>
          상단 내보내기나 그리드의 선택 추출 후 쌓입니다
        </CardEmpty>
      ) : (
        <ul className="dash-exports" aria-label="내보내기 이력">
          {entries.map((entry) => (
            <li key={`${entry.type}:${entry.name}`}>
              <span className="dash-export-name mono dash-wrap" title={entry.name}>
                {entry.name}
              </span>
              <span className="dash-note">
                {exportTypeLabel(entry)} · {formatTime(entry.created_at)} · {entry.status}
                {typeof entry.item_count === "number" ? ` · ${n(entry.item_count)}건` : ""}
              </span>
              <button
                type="button"
                className="button ghost icon-only"
                aria-label={`${entry.name} 내려받기`}
                onClick={() => {
                  downloadFile(entry.download_url, entry.name).catch((error: unknown) =>
                    announce(`내려받기 실패: ${error instanceof Error ? error.message : String(error)}`),
                  );
                }}
              >
                <Icon name="download" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// --- 키워드 일치 ---------------------------------------------------------------

/** Per-keyword match counts are fetched one after another (bounded `limit`) once the card is open. */
export const KEYWORD_COUNT_LIMIT = 100;

export function KeywordCard({
  runId,
  rows,
  enabled,
  onOpen,
}: {
  runId: string;
  rows: KeywordRow[];
  enabled: boolean;
  onOpen: (row: KeywordRow) => void;
}) {
  const results = useQueries({
    queries: rows.map((row) => ({
      queryKey: ["keyword-hits", runId, row.query, KEYWORD_COUNT_LIMIT],
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        getKeywordHitCount(runId, row.query, KEYWORD_COUNT_LIMIT, signal),
      enabled: false as boolean,
      retry: false,
      staleTime: 5 * 60_000,
    })),
  });
  // Sequential: row i starts once row i-1 has settled (avoids N parallel scans).
  const next = results.findIndex((result) => result.fetchStatus === "idle" && result.status === "pending");
  const anyFetching = results.some((result) => result.fetchStatus === "fetching");
  useEffect(() => {
    if (!enabled || anyFetching || next < 0) return;
    void results[next]?.refetch();
  }, [enabled, anyFetching, next, results]);

  if (rows.length === 0) {
    return (
      <CardEmpty title="키워드가 없습니다">
        런 모드에 기본 키워드가 없고 저장한 검색도 없습니다. 검색 노드에서 검색한 뒤 저장하면 여기에 건수가
        표시됩니다.
      </CardEmpty>
    );
  }
  return (
    <div className="dash-scroll">
      <table className="data-table dash-table" aria-label="키워드별 일치 건수">
        <thead>
          <tr>
            <th scope="col">키워드</th>
            <th scope="col">출처</th>
            <th scope="col" className="num">
              일치
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => {
            const result = results[index];
            const count = result?.data
              ? `${n(result.data.count)}${result.data.capped ? "+" : ""}`
              : result?.isError
                ? "오류"
                : enabled
                  ? null
                  : "—";
            return (
              <tr key={row.id}>
                <td className="dash-wrap">
                  <button
                    type="button"
                    className="dash-link"
                    onClick={() => onOpen(row)}
                    aria-label={`${row.label} 검색 열기`}
                  >
                    <Icon name="search" />
                    {row.label}
                  </button>
                </td>
                <td className="dash-note">{row.source === "profile" ? "런 모드" : "저장 검색"}</td>
                <td className="num" title={result?.isError ? String(result.error?.message ?? "") : undefined}>
                  {count ?? (
                    <span className="dash-pending" title="불러오는 중">
                      <Icon name="spinner" className="dash-spin" />
                      <span className="sr-only">불러오는 중</span>
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// --- 시작할 곳 ---------------------------------------------------------------------

export function StartCard({ onGo }: { onGo: (target: "search" | "artifacts" | "review") => void }) {
  const items = [
    {
      target: "search" as const,
      icon: "search" as const,
      label: "전체 검색",
      hint: "키워드로 파일·문서·아티팩트를 한 번에 찾습니다",
    },
    {
      target: "artifacts" as const,
      icon: "layers" as const,
      label: "아티팩트",
      hint: "범주·유형별로 분석 산출 항목을 봅니다",
    },
    {
      target: "review" as const,
      icon: "bookmark" as const,
      label: "리뷰보드",
      hint: "표시한 항목을 상태별로 검토합니다",
    },
  ];
  return (
    <ul className="dash-start">
      {items.map((item) => (
        <li key={item.target}>
          <button type="button" className="dash-start-item" onClick={() => onGo(item.target)}>
            <Icon name={item.icon} />
            <span>
              <b>{item.label}</b>
              <span className="dash-note">{item.hint}</span>
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}

// --- 처리 제한 사항 (처리 stage header) ---------------------------------------------

/** "단계 경고 N건" (+ " · 알림 M건" for notice-level messages: preview-only truncation). */
export function warningsSummary(warnings: RunWarning[]): string {
  const notices = warnings.filter(isNotice).length;
  const real = warnings.length - notices;
  return [real ? `단계 경고 ${n(real)}건` : "", notices ? `알림 ${n(notices)}건` : ""]
    .filter(Boolean)
    .join(" · ");
}

/** One disclosure line: label chip + text; raw ids only in the tooltip. */
export function DisclosureList({ items, label }: { items: DisclosureItem[]; label: string }) {
  return (
    <dl className="dash-disclosure-list" aria-label={label}>
      {items.map((item) => (
        <div key={item.id} className="dash-disclosure" data-tone={item.tone} title={item.detail}>
          <dt>
            <ToneChip tone={item.tone === "warn" ? "warn" : ""}>{item.label}</ToneChip>
          </dt>
          <dd>{item.text}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Step warnings as a list ("(알림)" marks notice-level lines); step ids read in Korean. */
export function WarningList({ warnings }: { warnings: RunWarning[] }) {
  return (
    <ul className="dash-issues">
      {warnings.slice(0, 100).map((warning, index) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: static read-only list
        <li key={index} data-level={warning.level || undefined}>
          <span className="dash-issue-step" title={warning.step ? String(warning.step) : undefined}>
            {warning.step ? stepLabelKo(String(warning.step)) : ""}
          </span>{" "}
          {isNotice(warning) ? "(알림) " : ""}
          {String(warning.message ?? "")}
        </li>
      ))}
    </ul>
  );
}

/**
 * 처리 제한 사항 (parser-quality r1; formerly 공개 사항): what this run could not do or did not do in
 * full — missing tools, caps, the evidence timezone, acquisition-copy times — plus the step
 * warnings. Used by the 처리 stage plan header; the 접수 dashboard shows the same lines in its
 * 처리 경고·제한 사항 card (caseCards.tsx WarningsCard).
 */
export function DisclosuresCard({ items, warnings }: { items: DisclosureItem[]; warnings: RunWarning[] }) {
  if (!items.length && !warnings.length) {
    return (
      <CardEmpty title="처리 제한 사항">
        이 런의 요약에는 처리 제한 사항이 없습니다 (이전 버전에서 처리한 런일 수 있습니다).
      </CardEmpty>
    );
  }
  return (
    <div className="dash-disclosures" data-testid="disclosures-card">
      {items.length ? <DisclosureList items={items} label="처리 제한 사항" /> : null}
      {warnings.length ? (
        <details className="dash-details">
          <summary>{warningsSummary(warnings)}</summary>
          <WarningList warnings={warnings} />
        </details>
      ) : null}
    </div>
  );
}
