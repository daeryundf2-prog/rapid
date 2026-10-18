/**
 * 검토 and 보고 stages (console-ia §3): the review board's statuses / tags / bookmarks as the
 * left panel (the centre stays the review grid), and the report page (exports, their
 * session history, and the run's output files).
 */

import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { getReviewCounts } from "../../api/caseDb";
import { getRunTree } from "../../api/runs";
import { CommandButton } from "../../commands/CommandButton";
import { serializeRoute } from "../../router";
import { useRoute, useTimezone } from "../../state/hooks";
import { formatTimestamp } from "../../utils/time";
import { EXPORT_ACTIONS, useExportHistory } from "../case/exports";
import { DataGrid } from "../grid/DataGrid";
import { useReviewMap } from "../grid/reviewMap";
import { TAG_MANAGER_COMMAND } from "../review/commands";
import { ReviewTagNodes } from "../review/ReviewTagNodes";
import { type CaseTagState, useCaseTags } from "../review/tagStore";
import {
  flagsPartialNotice,
  flagsUnavailableReason,
  NO_FLAGS_REASON,
  REVIEW_NODES,
  reviewCount,
  treeFlagsSection,
} from "../tree/model";
import "./stages.css";

const BOOKMARK_TAG = "북마크";

/** Left panel of the 검토 stage. */
export function ReviewPanel() {
  const { route } = useRoute();
  const runId = route.runId;
  const counts = useQuery({
    queryKey: ["review-counts", runId],
    queryFn: () => getReviewCounts(runId as string),
    enabled: Boolean(runId),
    retry: false,
  });
  const map = useReviewMap(runId);
  // 특이사항 shortcuts (U-F4): the same `/tree` summary the 탐색 tree shows (shared query key).
  const tree = useQuery({
    queryKey: ["run-tree", runId],
    queryFn: () => getRunTree(runId as string),
    enabled: Boolean(runId),
    retry: false,
    staleTime: 30_000,
  });
  const flags = treeFlagsSection(tree.data);
  const caseTags = useCaseTags(runId);
  const { tags, notes, bookmarks } = useMemo(() => {
    const byTag = new Map<string, number>();
    let withNote = 0;
    for (const mark of map?.values() ?? []) {
      for (const tag of mark.tags) byTag.set(tag, (byTag.get(tag) ?? 0) + 1);
      if (mark.note) withNote += 1;
    }
    return {
      tags: [...byTag.entries()].sort((a, b) => b[1] - a[1]),
      notes: withNote,
      // Same source as the link (review rows tagged 북마크).
      bookmarks: byTag.get(BOOKMARK_TAG) ?? 0,
    };
  }, [map]);
  if (!runId) return <p className="pane-empty">케이스를 먼저 선택하세요.</p>;
  const total = counts.data
    ? Object.values(counts.data.by_status ?? {}).reduce((sum, n) => sum + n, 0)
    : undefined;
  const onBoard = route.collection === "review";
  const link = (label: string, href: string, current: boolean, count?: number) => (
    <a className="stage-link" href={href} aria-current={current ? "page" : undefined}>
      <span>{label}</span>
      {count !== undefined ? <span className="badge muted">{count.toLocaleString("ko-KR")}</span> : null}
    </a>
  );
  return (
    <div className="stage-panel" data-testid="review-panel">
      <h2 id="review-status-title">리뷰 상태</h2>
      <ul aria-labelledby="review-status-title">
        <li>
          {link(
            "리뷰보드 전체",
            serializeRoute({ runId, collection: "review" }),
            onBoard && !route.status && !route.tags?.length && !route.notes,
            total,
          )}
        </li>
        {REVIEW_NODES.map(({ status, label }) => (
          <li key={status}>
            {link(
              label,
              serializeRoute({ runId, collection: "review", status }),
              onBoard && route.status === status,
              reviewCount(counts.data, status),
            )}
          </li>
        ))}
      </ul>
      <h2 id="review-flags-title">특이사항</h2>
      {flags ? (
        <>
          {flagsPartialNotice(tree.data) ? (
            <p className="stage-note" data-testid="review-flags-partial">
              {flagsPartialNotice(tree.data)}
            </p>
          ) : null}
          <ul aria-labelledby="review-flags-title" data-testid="review-flag-links">
            <li>
              {link(
                "특이사항 A 전체 보기",
                serializeRoute({ runId, collection: "artifacts", flagGrade: "A" }),
                false,
                flags.byGrade.A,
              )}
            </li>
            <li>
              {link(
                "특이사항 B 이상 보기",
                serializeRoute({ runId, collection: "artifacts", flagGrade: "B" }),
                false,
                flags.byGrade.A + flags.byGrade.B,
              )}
            </li>
          </ul>
        </>
      ) : (
        <p className="stage-note" data-testid="review-flags-missing">
          {tree.isLoading
            ? "특이사항 요약을 불러오는 중…"
            : (flagsUnavailableReason(tree.data) ?? NO_FLAGS_REASON)}
        </p>
      )}
      <h2 id="review-tags-title">태그·북마크</h2>
      <ul aria-labelledby="review-tags-title">
        <li>
          {link(
            "북마크",
            serializeRoute({ runId, collection: "review", tags: [BOOKMARK_TAG] }),
            onBoard && route.tags?.length === 1 && route.tags[0] === BOOKMARK_TAG,
            bookmarks,
          )}
        </li>
        <li>
          {link(
            "메모 있음",
            serializeRoute({ runId, collection: "review", notes: true }),
            onBoard && route.notes === true,
            notes,
          )}
        </li>
        {showCaseTagNodes(caseTags) ? (
          // Case tags (AXIOM E3): colour, key and the case DB's count per tag.
          <ReviewTagNodes
            runId={runId}
            tags={caseTags.tags}
            current={onBoard && route.tags?.length === 1 ? (route.tags[0] ?? null) : null}
          />
        ) : (
          tags
            .filter(([tag]) => tag !== BOOKMARK_TAG)
            .map(([tag, count]) => (
              <li key={tag}>
                {link(
                  `#${tag}`,
                  serializeRoute({ runId, collection: "review", tags: [tag] }),
                  onBoard && route.tags?.length === 1 && route.tags[0] === tag,
                  count,
                )}
              </li>
            ))
        )}
      </ul>
      <CommandButton command={TAG_MANAGER_COMMAND} label="태그 관리…" />
    </div>
  );
}

/**
 * The 검토 tree lists case tags (colour, key, case DB count) once they are known; until then —
 * first load, or no case DB — the review map's own tags, so the section never renders empty
 * while the tags load. A refresh of already-loaded tags keeps showing them (no flicker per mark).
 */
export function showCaseTagNodes(state: Pick<CaseTagState, "exists" | "status" | "tags">): boolean {
  return state.exists && (state.status === "ready" || state.tags.length > 0);
}

/** Left panel of the 보고 stage. */
export function ReportPanel() {
  const { route } = useRoute();
  if (!route.runId) return <p className="pane-empty">케이스를 먼저 선택하세요.</p>;
  return (
    <div className="stage-panel" data-testid="report-panel">
      <h2 id="report-actions-title">내보내기</h2>
      <ul aria-labelledby="report-actions-title">
        <li>
          <CommandButton command="export.open" label="보고서 내보내기…" />
        </li>
        {EXPORT_ACTIONS.map((action) => (
          <li key={action.commandId}>
            <CommandButton command={action.commandId} />
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Centre of the 보고 stage: export history of this session + the run's output files. */
export function ReportPage() {
  const { route } = useRoute();
  const { timezone } = useTimezone();
  const records = useExportHistory((s) => s.records);
  const runId = route.runId;
  const mine = records.filter((record) => record.runId === runId);
  if (!runId) return <p className="pane-empty">케이스를 먼저 선택하세요.</p>;
  return (
    <section className="stage-page is-report" aria-labelledby="report-title" data-testid="report-page">
      <h2 id="report-title">보고</h2>
      <section className="stage-section" aria-labelledby="report-history-title">
        <h3 id="report-history-title">내보내기 이력</h3>
        {mine.length === 0 ? (
          <p className="analysis-desc">
            이 세션에서 내보낸 파일이 없습니다. 왼쪽의 내보내기 명령으로 만듭니다.
          </p>
        ) : (
          <table className="analysis-history" aria-label="내보내기 이력">
            <thead>
              <tr>
                <th scope="col">종류</th>
                <th scope="col">파일</th>
                <th scope="col">시각</th>
              </tr>
            </thead>
            <tbody>
              {mine.map((record) => (
                <tr key={`${record.at}:${record.fileName}`}>
                  <td>{record.label}</td>
                  <td className="mono">{record.fileName}</td>
                  <td>{formatTimestamp(record.at, timezone)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <section className="stage-report-grid" aria-label="산출물">
        <DataGrid />
      </section>
    </section>
  );
}
