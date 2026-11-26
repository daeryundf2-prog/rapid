/**
 * Status line of the search workspace: what a running search is looking through and for how long
 * (with 취소), and the state of the run's search index (none, being built, stale) with the build
 * action. The grid's own wait panel stays off for the search collection, so the wait has one place.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { announce } from "../../a11y";
import { cancelAnalysis, isAnalysisActive } from "../../api/analyses";
import { WaitPanel, waitText } from "../../components/WaitPanel";
import { formatCount } from "../grid/gridUtils";
import { useNow } from "../stages/useNow";
import { useSearchActivity } from "./activity";
import { buildSearchIndex, type SearchIndexStatus } from "./api";
import { SEARCH_COUNT_KEY, SEARCH_INDEX_KEY, searchIndexQuery } from "./counts";
import { resetSearchCursors } from "./rows";

const SCAN_WAIT = "원본 스캔 중… 문서·파일·아티팩트·지표·타임라인 순서로 찾고 시간 제한에서 멈춥니다";

function searchQueries(runId: string) {
  return { queryKey: ["collection", runId, "search"] };
}

/** The run's index state; a finished build re-runs the searches on the new index. */
function useSearchIndex(runId: string) {
  const queryClient = useQueryClient();
  const status = useQuery(searchIndexQuery(runId));
  const state = status.data?.state;
  const wasBuilding = useRef(false);
  useEffect(() => {
    if (state === "building") {
      wasBuilding.current = true;
      return;
    }
    if (!wasBuilding.current || state === undefined) return;
    wasBuilding.current = false;
    // Old cursors and counts belong to the index that was replaced.
    resetSearchCursors();
    void queryClient.invalidateQueries(searchQueries(runId));
    void queryClient.invalidateQueries({ queryKey: [SEARCH_COUNT_KEY, runId] });
    if (state === "ready") announce("검색 색인을 만들었습니다. 색인으로 다시 검색합니다.");
  }, [state, runId, queryClient]);
  return status;
}

function BuildProgress({ runId, index }: { runId: string; index: SearchIndexStatus }) {
  const queryClient = useQueryClient();
  const build = index.building;
  const now = useNow(true);
  const started = build?.started_at ? Date.parse(build.started_at) : Number.NaN;
  const cancel = useMutation({
    mutationFn: () => cancelAnalysis(runId, build?.analysis_id ?? ""),
    onSettled: () => queryClient.invalidateQueries({ queryKey: [SEARCH_INDEX_KEY, runId] }),
  });
  if (!build || !isAnalysisActive(build)) return null;
  const { done, total, unit, message, percent } = build.progress;
  return (
    <p className="search-status-line" data-testid="search-index-building">
      <span>검색 색인 만드는 중</span>
      <progress
        value={total ? done : undefined}
        max={total ?? undefined}
        aria-label="검색 색인 만들기 진행"
      />
      {percent !== null ? <span className="num">{Math.round(percent)}%</span> : null}
      {total ? (
        <span className="num">
          {unit} {formatCount(done)}/{formatCount(total)}
        </span>
      ) : null}
      {message ? <span className="search-status-detail">{message}</span> : null}
      {Number.isFinite(started) ? (
        <span className="num">{waitText(Math.max(0, Math.floor((now - started) / 1000)))}</span>
      ) : null}
      <button type="button" className="button ghost" onClick={() => cancel.mutate()}>
        색인 만들기 취소
      </button>
    </p>
  );
}

/** Sentence and build label for an index that cannot answer, or answers from old data. */
function indexNotice(index: SearchIndexStatus): { text: string; action: string; primary: boolean } | null {
  const why = index.reason ? ` (${index.reason})` : "";
  switch (index.state) {
    case "none":
      return {
        text: "검색 색인이 없어 원본을 스캔합니다. 느리고 결과가 일부만 나올 수 있습니다.",
        action: "색인 만들기",
        primary: true,
      };
    case "corrupt":
      return {
        text: `검색 색인을 읽을 수 없어 원본을 스캔합니다${why}.`,
        action: "색인 다시 만들기",
        primary: true,
      };
    case "stale":
      return {
        text: `검색 색인이 런 출력보다 오래되어 결과가 최신이 아닐 수 있습니다${why}.`,
        action: "색인 다시 만들기",
        primary: false,
      };
    case "build-failed-swap":
      return {
        text: `새 색인으로 바꾸지 못해 이전 색인으로 검색합니다${why}.`,
        action: "색인 다시 만들기",
        primary: false,
      };
    case "building":
    case "ready":
      return null;
  }
}

export function SearchStatus({ runId }: { runId: string }) {
  const queryClient = useQueryClient();
  const pending = useSearchActivity((s) => s.pending);
  const cancelled = useSearchActivity((s) => s.cancelled);
  const scanReason = useSearchActivity((s) => s.scanReason);
  const arrived = useSearchActivity((s) => s.arrived);
  const index = useSearchIndex(runId).data;
  const build = useMutation({
    mutationFn: () => buildSearchIndex(runId),
    onSettled: () => queryClient.invalidateQueries({ queryKey: [SEARCH_INDEX_KEY, runId] }),
  });
  const cancelSearch = () => {
    useSearchActivity.getState().cancel();
    void queryClient.cancelQueries(searchQueries(runId));
    announce("검색을 취소했습니다.");
  };
  const notice = index && !scanReason ? indexNotice(index) : null;
  const warnings = arrived?.backend === "index" ? arrived.warnings : [];
  const waitLabel =
    pending === "scan"
      ? SCAN_WAIT
      : index?.docCount
        ? `색인 문서 ${formatCount(index.docCount)}건에서 찾는 중…`
        : "색인에서 찾는 중…";
  if (!pending && !cancelled && !scanReason && !notice && !index?.building && warnings.length === 0) {
    return null;
  }
  return (
    <div className="search-status" data-testid="search-status">
      {pending ? (
        <WaitPanel label={waitLabel} className="search-status-line" testId="search-wait">
          <button type="button" className="button ghost" onClick={cancelSearch}>
            검색 취소
          </button>
        </WaitPanel>
      ) : cancelled ? (
        <p className="search-status-line" data-testid="search-cancelled">
          <span>검색을 취소했습니다.</span>
          <button
            type="button"
            className="button ghost"
            onClick={() => void queryClient.refetchQueries(searchQueries(runId))}
          >
            다시 검색
          </button>
        </p>
      ) : null}
      {scanReason ? <p className="search-status-line">{scanReason}</p> : null}
      {index ? <BuildProgress runId={runId} index={index} /> : null}
      {notice ? (
        <p className="search-status-line" data-testid="search-index-notice">
          <span>{notice.text}</span>
          <button
            type="button"
            className={notice.primary ? "button primary" : "button"}
            // One request per build: a second press while it is being queued does nothing.
            onClick={() => (build.isPending ? undefined : build.mutate())}
          >
            {notice.action}
          </button>
        </p>
      ) : null}
      {build.error ? (
        <p className="search-status-line search-status-error" role="alert">
          색인을 만들지 못했습니다. {build.error.message}
        </p>
      ) : null}
      {warnings.map((warning) => (
        <p key={warning} className="search-status-line" role="note">
          {warning}
        </p>
      ))}
    </div>
  );
}
