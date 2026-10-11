/**
 * 접수 dashboard cards (plan §9 X1). Each card receives its query results and
 * a navigation callback; data shaping lives in ./model.ts.
 */

import { useMutation, useQueries, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useEffect, useId, useState } from "react";
import { announce } from "../../a11y";
import { downloadFile } from "../../api/client";
import {
  type CaseNotes,
  type EvidenceSource,
  type ExportEntry,
  getKeywordHitCount,
  saveCaseNotes,
} from "../../api/dashboard";
import type { CanonicalCounts, ItemRow } from "../../api/runs";
import { RUN_MODE_LABEL } from "../../app/collections";
import { StatusBadge } from "../../components/Badge";
import type { ReviewStatus } from "../../contracts/collection";
import { Icon } from "../../icons";
import { formatBytes, partitionLabel } from "../tree/model";
import { CardEmpty } from "./Card";
import {
  type CategoryBar,
  evidenceItemCount,
  exportTypeLabel,
  formatDuration,
  formatTime,
  type KeywordRow,
  type ReviewSummaryRow,
  type StageRow,
} from "./model";
import type { ProviderProgress, RunDetail } from "./useDashboardData";

const n = (value: number) => value.toLocaleString("ko-KR");

// --- 케이스 요약 노트 ---------------------------------------------------------

export function CaseNotesCard({ runId, notes }: { runId: string; notes: CaseNotes | undefined }) {
  const client = useQueryClient();
  const [examiner, setExaminer] = useState("");
  const [summary, setSummary] = useState("");
  const [dirty, setDirty] = useState(false);
  const examinerId = useId();
  const summaryId = useId();
  const noteStateId = useId();

  useEffect(() => {
    if (notes && !dirty) {
      setExaminer(notes.examiner);
      setSummary(notes.summary);
    }
  }, [notes, dirty]);

  const save = useMutation<CaseNotes, Error>({
    mutationFn: () => saveCaseNotes(runId, { examiner, summary }),
    onSuccess: (saved) => {
      client.setQueryData(["case-notes", runId], saved);
      setDirty(false);
      announce("케이스 요약 노트를 저장했습니다");
    },
    onError: (error: unknown) =>
      announce(`노트 저장 실패: ${error instanceof Error ? error.message : String(error)}`, {
        politeness: "assertive",
      }),
  });

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (!save.isPending) save.mutate();
  };

  return (
    <form className="dash-notes" onSubmit={onSubmit} aria-busy={save.isPending}>
      <label htmlFor={examinerId}>검사자 이름</label>
      <input
        id={examinerId}
        className="dash-input"
        value={examiner}
        maxLength={200}
        placeholder="예: 홍길동 (디지털포렌식팀)"
        onChange={(event) => {
          setExaminer(event.target.value);
          setDirty(true);
        }}
      />
      <label htmlFor={summaryId}>케이스 요약</label>
      <textarea
        id={summaryId}
        className="dash-input"
        rows={4}
        maxLength={20000}
        value={summary}
        placeholder="사건 개요, 분석 목적, 주의할 점을 적어 두면 보고서의 분석 범위에 들어갑니다."
        onChange={(event) => {
          setSummary(event.target.value);
          setDirty(true);
        }}
      />
      <div className="dash-notes-foot">
        <button
          type="submit"
          className="button primary"
          aria-disabled={save.isPending || !dirty || undefined}
          aria-describedby={save.isPending || !dirty ? noteStateId : undefined}
        >
          {save.isPending ? "저장 중…" : "저장"}
        </button>
        {/* Saves/failures are announced through the shell live region (announce()). */}
        <span className="dash-note" id={noteStateId}>
          {dirty
            ? "저장하지 않은 변경이 있습니다"
            : notes?.updated_at
              ? `저장됨 · ${formatTime(notes.updated_at)}`
              : "아직 저장된 노트가 없습니다"}
        </span>
      </div>
      {save.isError ? (
        <p className="error-banner">
          저장하지 못했습니다: {save.error instanceof Error ? save.error.message : String(save.error)}
        </p>
      ) : null}
      <p className="dash-note">
        검사자 이름과 요약은 케이스 보고서의 분석자·분석 범위가 비어 있을 때 채워집니다.
      </p>
    </form>
  );
}

// --- 케이스 처리 세부 ---------------------------------------------------------

const PROVIDER_STATUS: Record<string, string> = {
  queued: "대기",
  running: "실행 중",
  completed: "완료",
  error: "오류",
  reused: "재사용",
};

export function ProcessingCard({
  run,
  stages,
  issues,
  onOpenOutputs,
}: {
  run: RunDetail;
  stages: StageRow[];
  issues: ItemRow[] | undefined;
  onOpenOutputs: () => void;
}) {
  const progress = run.progress ?? null;
  const providers = Object.entries(progress?.providers ?? {}).sort(([a], [b]) => a.localeCompare(b)) as Array<
    [string, ProviderProgress]
  >;
  const completed = run.status === "completed";
  return (
    <div className="dash-processing">
      <dl className="detail-grid">
        <dt>상태</dt>
        <dd>
          <StatusBadge status={String(run.status)} />
        </dd>
        <dt>런 ID</dt>
        <dd className="mono">{run.run_id}</dd>
        <dt>모드</dt>
        <dd>{RUN_MODE_LABEL[run.request?.mode ?? ""] ?? run.request?.mode ?? "—"}</dd>
        <dt>증거 경로</dt>
        <dd className="mono break-all">{run.request?.root || "—"}</dd>
        <dt>시작</dt>
        <dd>{formatTime(progress?.started_at ?? run.created_at)}</dd>
        <dt>완료</dt>
        <dd>{completed ? formatTime(progress?.completed_at ?? run.updated_at) : "—"}</dd>
      </dl>
      {run.error ? <p className="error-banner">{run.error}</p> : null}
      {progress?.error ? (
        <p className="error-banner">
          {progress.error.stage} 단계 오류: {progress.error.message}
        </p>
      ) : null}
      {stages.length ? (
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
                <td className="mono">{stage.stage}</td>
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
      ) : (
        <p className="dash-note">진행 기록이 없습니다 (가져온 런이거나 진행 파일이 없는 런입니다).</p>
      )}
      {providers.length ? (
        <details className="dash-details">
          <summary>
            provider {progress?.completed_count ?? 0}/{progress?.total_count ?? providers.length} · 오류{" "}
            {progress?.error_count ?? 0}
          </summary>
          <table className="data-table dash-table" aria-label="provider 진행">
            <thead>
              <tr>
                <th scope="col">provider</th>
                <th scope="col">상태</th>
                <th scope="col">소요</th>
                <th scope="col">건수</th>
              </tr>
            </thead>
            <tbody>
              {providers.map(([kind, p]) => (
                <tr key={kind}>
                  <td className="mono">{kind}</td>
                  <td>{PROVIDER_STATUS[p.status ?? ""] ?? p.status ?? "—"}</td>
                  <td>{formatDuration(p.duration_ms)}</td>
                  <td>{typeof p.artifact_count === "number" ? n(p.artifact_count) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      ) : null}
      {issues?.length ? (
        <details className="dash-details">
          <summary>검증 이슈 {n(issues.length)}건</summary>
          <ul className="dash-issues">
            {issues.slice(0, 100).map((issue, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: static read-only list
              <li key={index}>
                <span className="mono">{String(issue.step ?? "")}</span> {String(issue.message ?? "")}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
      <button
        type="button"
        className="button"
        onClick={onOpenOutputs}
        aria-disabled={completed ? undefined : true}
        title={completed ? undefined : "런이 완료되면 산출물을 볼 수 있습니다"}
      >
        <Icon name="report" /> 스캔 요약 보기
      </button>
    </div>
  );
}

// --- 증거 소스 ---------------------------------------------------------------

export function EvidenceCard({
  source,
  counts,
  onOpenFiles,
}: {
  source: EvidenceSource;
  counts: CanonicalCounts | undefined;
  onOpenFiles: () => void;
}) {
  const items = evidenceItemCount(counts);
  const selected = source.partitions.find((partition) => partition.selected);
  return (
    <div className="dash-evidence">
      <p className="dash-evidence-name">
        <Icon name={source.kind === "folder" ? "folder" : "hard-drive"} size={18} />
        <span className="mono break-all">{source.name}</span>
        {items !== undefined ? <span className="badge muted">{n(items)}</span> : null}
      </p>
      <dl className="detail-grid">
        <dt>유형</dt>
        <dd>{source.kind === "image" ? "디스크 이미지" : source.kind === "file" ? "파일" : "폴더"}</dd>
        <dt>크기</dt>
        <dd>{formatBytes(source.size_bytes)}</dd>
        <dt>위치</dt>
        <dd className="mono break-all">{source.path || "—"}</dd>
        <dt>항목 수</dt>
        <dd>
          {items !== undefined
            ? `${n(items)} (파일 ${n(counts?.files ?? 0)} + 아티팩트 ${n(counts?.artifacts ?? 0)})`
            : "런이 완료되면 표시됩니다"}
        </dd>
        <dt>선택 파티션</dt>
        <dd>{selected ? partitionLabel(selected) : source.partitions.length ? "선택 기록 없음" : "—"}</dd>
      </dl>
      {source.partitions.length ? (
        <table className="data-table dash-table" aria-label="파티션">
          <thead>
            <tr>
              <th scope="col">번호</th>
              <th scope="col">파일 시스템</th>
              <th scope="col">크기</th>
              <th scope="col">복구 대상</th>
            </tr>
          </thead>
          <tbody>
            {source.partitions.map((partition) => (
              <tr key={partition.number} className={partition.selected ? "selected" : undefined}>
                <td>{partition.number}</td>
                <td title={partition.description}>
                  {partition.filesystem === "unknown" ? "알 수 없음" : partition.filesystem.toUpperCase()}
                </td>
                <td>{formatBytes(partition.size_bytes)}</td>
                <td>
                  {partition.selected ? (
                    <button type="button" className="button ghost" onClick={onOpenFiles}>
                      선택됨 · 파일 보기
                    </button>
                  ) : (
                    <span className="dash-note">{partition.recommended ? "권장" : "—"}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="dash-note">
          {source.kind === "image"
            ? "이미지 단계가 파티션 표를 기록하지 않았습니다."
            : "폴더·파일 증거에는 파티션이 없습니다."}
        </p>
      )}
    </div>
  );
}

// --- 아티팩트 범주 -----------------------------------------------------------

export function CategoryCard({
  bars,
  total,
  sourceName,
  onOpenCategory,
}: {
  bars: CategoryBar[];
  total: number;
  sourceName: string | undefined;
  onOpenCategory: (category: string) => void;
}) {
  const selectId = useId();
  return (
    <div className="dash-categories">
      <div className="dash-row">
        <label htmlFor={selectId} className="dash-note">
          증거 소스
        </label>
        <select
          id={selectId}
          className="dash-input"
          aria-disabled="true"
          title="여러 증거 소스를 한 케이스에 묶는 기능은 아직 없습니다"
          value="all"
          onChange={() => undefined}
        >
          <option value="all">{sourceName ? `전체 (${sourceName})` : "전체"}</option>
        </select>
      </div>
      {bars.length === 0 ? (
        <CardEmpty title="아티팩트가 없습니다">
          이 런의 수집 모드에서 아티팩트 수집기가 결과를 내지 않았습니다. 파일·문서 노드에서 항목을
          확인하세요.
        </CardEmpty>
      ) : (
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
                  <Icon name={bar.category.icon} size={14} />
                  {bar.category.label}
                </span>
                <span className="dash-bar-track" aria-hidden="true">
                  <span
                    className="dash-bar-fill"
                    style={{ inlineSize: `${Math.max(2, bar.ratio * 100)}%` }}
                  />
                </span>
                <span className="dash-bar-count">{n(bar.count)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// --- 태그 및 리뷰 상태 ---------------------------------------------------------

export function ReviewCard({
  rows,
  onOpenStatus,
}: {
  rows: ReviewSummaryRow[];
  onOpenStatus: (status: ReviewStatus | undefined) => void;
}) {
  const empty = rows.every((row) => row.count === 0);
  return (
    <div>
      <table className="data-table dash-table" aria-label="리뷰 상태별 건수">
        <thead>
          <tr>
            <th scope="col">상태</th>
            <th scope="col" className="num">
              건수
            </th>
          </tr>
        </thead>
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
      {empty ? (
        <p className="dash-note">
          아직 표시한 항목이 없습니다. 그리드에서 R(관련 있음)·I(재검토)·X(제외)·B(보고서 포함)로 표시하면
          여기에 집계됩니다.
        </p>
      ) : null}
    </div>
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
                ? "…"
                : "—";
          return (
            <tr key={row.id}>
              <td>
                <button
                  type="button"
                  className="dash-link"
                  onClick={() => onOpen(row)}
                  aria-label={`${row.label} 검색 열기`}
                >
                  <Icon name="search" size={14} />
                  {row.label}
                </button>
              </td>
              <td className="dash-note">{row.source === "profile" ? "런 모드" : "저장 검색"}</td>
              <td className="num" title={result?.isError ? String(result.error?.message ?? "") : undefined}>
                {count}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// --- 내보내기 / 보고서 이력 --------------------------------------------------------

export function ExportsCard({ entries }: { entries: ExportEntry[] }) {
  if (entries.length === 0) {
    return (
      <CardEmpty title="아직 내보낸 보고서나 추출 파일이 없습니다">
        보고서 포함으로 표시한 뒤 상단의 내보내기(보고서·리뷰어 번들)나 그리드의 선택 추출을 실행하면 이력이
        쌓입니다.
      </CardEmpty>
    );
  }
  return (
    <table className="data-table dash-table" aria-label="내보내기 이력">
      <thead>
        <tr>
          <th scope="col">이름</th>
          <th scope="col">유형</th>
          <th scope="col">날짜</th>
          <th scope="col">상태</th>
          <th scope="col">
            <span className="visually-hidden">내려받기</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {entries.map((entry) => (
          <tr key={`${entry.type}:${entry.name}`}>
            <td className="mono break-all" title={entry.name}>
              {entry.name}
            </td>
            <td>{exportTypeLabel(entry)}</td>
            <td>{formatTime(entry.created_at)}</td>
            <td>
              {entry.status}
              {typeof entry.item_count === "number" ? ` · ${n(entry.item_count)}건` : ""}
            </td>
            <td>
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
            </td>
          </tr>
        ))}
      </tbody>
    </table>
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
            <Icon name={item.icon} size={20} />
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
