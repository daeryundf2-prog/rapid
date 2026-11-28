/**
 * 검토 and 보고 stages (console-ia §3).
 *
 * 검토: the left panel filters the review board by 판정 (only the ones present), by 판정자 (the
 * people who decided, and 이름 없음), by 특이사항 grade (each explained in one line) and by
 * tags / bookmarks. The centre stays the review grid.
 *
 * 보고 (design review F16): the page is a checklist first (what is in the report, what is 관련 있음
 * but left out, unverified evidence, unnamed decisions), then the items the report will carry,
 * then ONE primary export with the other formats under it (each says who it is for; a disabled
 * one says why in text). The run's output files fold into a closed section.
 */

import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { announce } from "../../a11y/announcer";
import { getReviewCounts } from "../../api/caseDb";
import { getCase } from "../../api/cases";
import { fetchOutputRows } from "../../api/collections";
import { getRunTree } from "../../api/runs";
import { CommandButton } from "../../commands/CommandButton";
import { useCommandState } from "../../commands/registry";
import type { GridRow } from "../../contracts/collection";
import { serializeRoute } from "../../router";
import { useRoute, useTimezone } from "../../state/hooks";
import { formatGridTime, formatTimestamp } from "../../utils/time";
import { useCaseLinks } from "../case/caseLink";
import { EXPORT_ACTIONS, useExportHistory } from "../case/exports";
import { ReasonButton } from "../case/ReasonButton";
import { REVIEW_LABELS, rowTimeZone } from "../grid/columns/common";
import { hasVerdict } from "../grid/columns/review";
import { DataGrid } from "../grid/DataGrid";
import { applyReviewAction } from "../grid/reviewActions";
import { useReviewMap } from "../grid/reviewMap";
import {
  hashCheck,
  NOT_IN_REPORT_FILTER,
  reportChecklist,
  reviewerCounts,
  reviewerFilter,
  useReviewBoardRows,
} from "../review/boardModel";
import { TAG_MANAGER_COMMAND } from "../review/commands";
import { FILE_TIME_QUALIFIER } from "../review/ReviewBoardCells";
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

/** One line per 특이사항 grade link: what the grade means (the rule catalogue's grading). */
export const FLAG_GRADE_HELP = {
  A: "흔적 지우기·외부 IP 원격 접속처럼 사건과 바로 이어질 수 있는 강한 단서",
  B: "A에 주의 단서(B)까지: 더 넓게 보되 오탐도 늘어납니다",
} as const;

const n = (value: number) => value.toLocaleString("ko-KR");

function useReviewCounts(runId: string | null) {
  return useQuery({
    queryKey: ["review-counts", runId],
    queryFn: () => getReviewCounts(runId as string),
    enabled: Boolean(runId),
    retry: false,
  });
}

/** Left panel of the 검토 stage. */
export function ReviewPanel() {
  const { route } = useRoute();
  const runId = route.runId;
  const counts = useReviewCounts(runId);
  const map = useReviewMap(runId);
  const board = useReviewBoardRows(runId);
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
  const rows = board.data;
  const reviewers = useMemo(() => (rows ? reviewerCounts(rows) : []), [rows]);
  const leftOut = useMemo(() => (rows ? reportChecklist(rows).relevantLeftOut.length : 0), [rows]);
  if (!runId) return <p className="pane-empty">케이스를 먼저 선택하세요.</p>;
  const total = counts.data
    ? Object.values(counts.data.by_status ?? {}).reduce((sum, value) => sum + value, 0)
    : undefined;
  const onBoard = route.collection === "review";
  const reviewerOn = onBoard ? route.cf?.find((f) => f.col === "reviewer")?.value : undefined;
  const leftOutOn =
    onBoard &&
    route.status === "relevant" &&
    route.cf?.some((f) => f.col === "report" && f.value === "미포함");
  const link = (label: string, href: string, current: boolean, count?: number) => (
    <a className="stage-link" href={href} aria-current={current ? "page" : undefined}>
      <span>{label}</span>
      {count !== undefined ? <span className="badge muted">{n(count)}</span> : null}
    </a>
  );
  // F12: a 판정 nobody made is not a filter; the one in the URL stays reachable.
  const statusNodes = REVIEW_NODES.filter(({ status }) => {
    const count = reviewCount(counts.data, status);
    return count === undefined || count > 0 || (onBoard && route.status === status);
  });
  const gradeA = flags?.byGrade.A ?? 0;
  const gradeB = gradeA + (flags?.byGrade.B ?? 0);
  return (
    <div className="stage-panel" data-testid="review-panel">
      <h2 id="review-status-title">판정</h2>
      <ul aria-labelledby="review-status-title">
        <li>
          {link(
            "검토 보드 전체",
            serializeRoute({ runId, collection: "review" }),
            onBoard && !route.status && !route.tags?.length && !route.notes && !route.cf?.length,
            total,
          )}
        </li>
        {statusNodes.map(({ status, label }) => (
          <li key={status}>
            {link(
              label,
              serializeRoute({ runId, collection: "review", status }),
              onBoard && route.status === status && !leftOutOn,
              reviewCount(counts.data, status),
            )}
          </li>
        ))}
        {leftOut > 0 ? (
          <li>
            {link(
              "관련 있음 중 보고서 미포함",
              serializeRoute({ runId, collection: "review", status: "relevant", cf: NOT_IN_REPORT_FILTER }),
              Boolean(leftOutOn),
              leftOut,
            )}
          </li>
        ) : null}
      </ul>
      {counts.data && statusNodes.length === 0 ? (
        <p className="stage-note">아직 판정한 항목이 없습니다. 탐색에서 행을 고르고 R·X·I로 판정합니다.</p>
      ) : null}
      {reviewers.length > 0 ? (
        <>
          <h2 id="review-reviewer-title">판정자</h2>
          <ul aria-labelledby="review-reviewer-title" data-testid="review-reviewer-links">
            {reviewers.map(({ label, count }) => (
              <li key={label}>
                {link(
                  label,
                  serializeRoute({ runId, collection: "review", cf: reviewerFilter(label) }),
                  reviewerOn === label,
                  count,
                )}
              </li>
            ))}
          </ul>
        </>
      ) : null}
      <h2 id="review-flags-title">특이사항</h2>
      {flags ? (
        <>
          {flagsPartialNotice(tree.data) ? (
            <p className="stage-note" data-testid="review-flags-partial">
              {flagsPartialNotice(tree.data)}
            </p>
          ) : null}
          {gradeB > 0 ? (
            <ul aria-labelledby="review-flags-title" data-testid="review-flag-links">
              {gradeA > 0 ? (
                <li>
                  {link(
                    "특이사항 A",
                    serializeRoute({ runId, collection: "artifacts", flagGrade: "A" }),
                    false,
                    gradeA,
                  )}
                  <p className="stage-link-help">{FLAG_GRADE_HELP.A}</p>
                </li>
              ) : null}
              <li>
                {link(
                  "특이사항 B 이상",
                  serializeRoute({ runId, collection: "artifacts", flagGrade: "B" }),
                  false,
                  gradeB,
                )}
                <p className="stage-link-help">{FLAG_GRADE_HELP.B}</p>
              </li>
            </ul>
          ) : (
            <p className="stage-note" data-testid="review-flags-none">
              이 런에서 A·B 등급 특이사항에 걸린 행이 없습니다.
            </p>
          )}
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
        {bookmarks > 0 || (onBoard && route.tags?.length === 1 && route.tags[0] === BOOKMARK_TAG) ? (
          <li>
            {link(
              "북마크",
              serializeRoute({ runId, collection: "review", tags: [BOOKMARK_TAG] }),
              onBoard && route.tags?.length === 1 && route.tags[0] === BOOKMARK_TAG,
              bookmarks,
            )}
          </li>
        ) : null}
        {notes > 0 || (onBoard && route.notes === true) ? (
          <li>
            {link(
              "메모 있음",
              serializeRoute({ runId, collection: "review", notes: true }),
              onBoard && route.notes === true,
              notes,
            )}
          </li>
        ) : null}
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

/** In-page sections of the 보고 page (the left panel jumps to them). */
const REPORT_SECTIONS = [
  { id: "report-check", label: "보고 전 점검" },
  { id: "report-preview", label: "보고서에 들어갈 항목" },
  { id: "report-export", label: "내보내기" },
  { id: "report-outputs", label: "처리 결과 파일" },
] as const;

/** Left panel of the 보고 stage: the page's sections (the export actions live in the page body). */
export function ReportPanel() {
  const { route } = useRoute();
  if (!route.runId) return <p className="pane-empty">케이스를 먼저 선택하세요.</p>;
  return (
    <nav className="stage-panel" aria-labelledby="report-sections-title" data-testid="report-panel">
      <h2 id="report-sections-title">보고 화면</h2>
      <ul>
        {REPORT_SECTIONS.map((section) => (
          <li key={section.id}>
            <button
              type="button"
              className="stage-link"
              onClick={() => {
                const target = document.getElementById(section.id);
                target?.scrollIntoView({ block: "start" });
                target?.focus({ preventScroll: true });
              }}
            >
              <span>{section.label}</span>
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
}

/** "2026-10-18 08:02:48 KST", with "파일 수정" for a file copy's mtime; "사건 시각 없음" when none. */
function eventTimeText(row: GridRow, tz: string): string {
  if (!row.timestamp) return "사건 시각 없음";
  const text = formatGridTime(row.timestamp, tz, rowTimeZone(row));
  return row.fields.timeKind === "file-mtime" ? `${text} (${FILE_TIME_QUALIFIER})` : text;
}

/** Preview rows shown at once; the export carries every included item. */
const PREVIEW_LIMIT = 200;

/** Centre of the 보고 stage. */
export function ReportPage() {
  const { route } = useRoute();
  const { timezone } = useTimezone();
  const runId = route.runId;
  const records = useExportHistory((s) => s.records);
  const counts = useReviewCounts(runId);
  const board = useReviewBoardRows(runId);
  const caseId = useCaseLinks((s) => (runId ? (s.byRun[runId]?.caseId ?? null) : null));
  const caseQuery = useQuery({
    queryKey: ["case", caseId],
    queryFn: () => getCase(caseId as string),
    enabled: Boolean(caseId),
    retry: false,
  });
  const outputs = useQuery({
    queryKey: ["output-files", runId],
    queryFn: ({ signal }) => fetchOutputRows(runId as string, signal),
    enabled: Boolean(runId),
    retry: false,
    staleTime: 30_000,
  });
  const report = useCommandState("export.case-report");
  const openDialog = useCommandState("export.open");
  const [outputsOpen, setOutputsOpen] = useState(route.collection === "outputs" && Boolean(route.row));
  const [including, setIncluding] = useState(false);
  const [message, setMessage] = useState<{ text: string; tone: "info" | "error" } | null>(null);
  const check = useMemo(() => reportChecklist(board.data ?? []), [board.data]);
  if (!runId) return <p className="pane-empty">케이스를 먼저 선택하세요.</p>;
  const mine = records.filter((record) => record.runId === runId);
  const hashes = caseQuery.data ? hashCheck(caseQuery.data.evidence) : null;
  const bookmarkIncluded = counts.data?.case_json.include_in_report ?? 0;
  const outputCount = outputs.data?.rows.length;

  const includeRelevant = async () => {
    if (including || check.relevantLeftOut.length === 0) return;
    setIncluding(true);
    setMessage(null);
    try {
      const result = await applyReviewAction(runId, check.relevantLeftOut, "include-in-report");
      const text = `관련 있음 ${n(result.applied)}건을 보고서에 포함했습니다.`;
      setMessage({ text, tone: "info" });
      announce(text);
    } catch (error) {
      const text = `보고서에 포함하지 못했습니다. ${error instanceof Error ? error.message : String(error)}`;
      setMessage({ text, tone: "error" });
      announce(text, { politeness: "assertive" });
    } finally {
      setIncluding(false);
    }
  };

  return (
    <section className="stage-page is-report" aria-labelledby="report-title" data-testid="report-page">
      <h2 id="report-title">보고</h2>

      <section
        className="stage-section report-check"
        id="report-check"
        tabIndex={-1}
        aria-labelledby="report-check-title"
      >
        <h3 id="report-check-title">보고 전 점검</h3>
        {board.isPending ? (
          <p className="analysis-desc">판정 목록을 불러오는 중…</p>
        ) : (
          <ul className="report-checklist" data-testid="report-checklist">
            <li data-state={check.included.length + bookmarkIncluded > 0 ? "ok" : "todo"}>
              <span className="report-check-label">보고서 포함</span>
              <strong className="report-check-count">{n(check.included.length)}건</strong>
              {check.included.length === 0 ? (
                <span className="report-check-help">
                  아직 없습니다. 검토 보드에서 행의 ⋯ 메뉴(행 메뉴) › ‘보고서 포함 표시’로 넣습니다.
                </span>
              ) : null}
              {bookmarkIncluded > 0 ? (
                <span className="report-check-help">
                  case.json 북마크 {n(bookmarkIncluded)}건도 함께 나갑니다.
                </span>
              ) : null}
            </li>
            <li
              data-state={check.relevantLeftOut.length > 0 ? "todo" : "ok"}
              data-testid="report-check-left-out"
            >
              <span className="report-check-label">관련 있음 중 보고서 미포함</span>
              <strong className="report-check-count">{n(check.relevantLeftOut.length)}건</strong>
              {check.relevantLeftOut.length > 0 ? (
                <span className="report-check-actions">
                  <button
                    type="button"
                    className="button"
                    disabled={including}
                    data-testid="report-include-relevant"
                    onClick={() => void includeRelevant()}
                  >
                    관련 있음 {n(check.relevantLeftOut.length)}건 보고서에 포함
                  </button>
                  <a
                    className="report-check-link"
                    href={serializeRoute({
                      runId,
                      collection: "review",
                      status: "relevant",
                      cf: NOT_IN_REPORT_FILTER,
                    })}
                  >
                    검토 보드에서 하나씩 보기
                  </a>
                </span>
              ) : null}
            </li>
            <li
              data-state={
                hashes ? (hashes.broken > 0 ? "bad" : hashes.unverified > 0 ? "todo" : "ok") : "unknown"
              }
            >
              <span className="report-check-label">해시 대조 안 된 증거</span>
              {hashes ? (
                <>
                  <strong className="report-check-count">{n(hashes.unverified + hashes.broken)}건</strong>
                  <span className="report-check-help">
                    {hashes.broken > 0 ? `불일치·실패 ${n(hashes.broken)}건, ` : ""}
                    증거 {n(hashes.total)}건 중 대조 일치 {n(hashes.matched)}건
                  </span>
                  {hashes.unverified + hashes.broken > 0 ? (
                    <a className="report-check-link" href={serializeRoute({ runId, collection: "intake" })}>
                      접수에서 확인
                    </a>
                  ) : null}
                </>
              ) : (
                <span className="report-check-help">
                  {caseId
                    ? caseQuery.isError
                      ? "케이스 증거 정보를 읽지 못했습니다."
                      : "확인 중…"
                    : "케이스에 연결되지 않은 런이라 증거 해시 정보가 없습니다."}
                </span>
              )}
            </li>
            <li data-state={check.unnamed > 0 ? "todo" : "ok"}>
              <span className="report-check-label">판정자 이름 없는 판정</span>
              <strong className="report-check-count">{n(check.unnamed)}건</strong>
              {check.unnamed > 0 ? (
                <>
                  <span className="report-check-help">
                    {check.unnamedIncluded > 0 ? `보고서 포함 항목 중 ${n(check.unnamedIncluded)}건. ` : ""}
                    누가 판정했는지 기록에 이름이 없습니다(보고서 본문에는 판정자가 들어가지 않습니다).
                  </span>
                  <a
                    className="report-check-link"
                    href={serializeRoute({ runId, collection: "review", cf: reviewerFilter("이름 없음") })}
                  >
                    검토 보드에서 보기
                  </a>
                </>
              ) : null}
            </li>
          </ul>
        )}
        {message ? (
          <p className={`report-check-message${message.tone === "error" ? " is-error" : ""}`}>
            {message.text}
          </p>
        ) : null}
      </section>

      <section
        className="stage-section"
        id="report-preview"
        tabIndex={-1}
        aria-labelledby="report-preview-title"
      >
        <h3 id="report-preview-title">
          보고서에 들어갈 항목 {board.data ? `${n(check.included.length)}건` : ""}
        </h3>
        {check.included.length === 0 ? (
          <p className="analysis-desc">보고서에 포함한 항목이 없습니다.</p>
        ) : (
          <>
            <table className="report-preview" aria-label="보고서에 들어갈 항목" data-testid="report-preview">
              <thead>
                <tr>
                  <th scope="col">판정</th>
                  <th scope="col">대상</th>
                  <th scope="col">사건 시각</th>
                  <th scope="col">메모</th>
                  <th scope="col">출처 경로</th>
                </tr>
              </thead>
              <tbody>
                {check.included.slice(0, PREVIEW_LIMIT).map((row) => (
                  <tr key={row.rowKey}>
                    <td data-label="판정">
                      {/* The stored verdict, as the report's 검토 상태 says it (every row here is 보고서 포함). */}
                      {row.reviewStatus && hasVerdict(row) ? REVIEW_LABELS[row.reviewStatus] : "판정 없음"}
                    </td>
                    <td data-label="대상" className="report-preview-target">
                      {row.title}
                    </td>
                    <td data-label="사건 시각">{eventTimeText(row, timezone)}</td>
                    <td data-label="메모">{String(row.fields.note ?? "") || "메모 없음"}</td>
                    <td data-label="출처 경로" className="report-preview-path">
                      {row.sourcePath ?? "경로 없음"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {check.included.length > PREVIEW_LIMIT ? (
              <p className="analysis-desc">
                처음 {n(PREVIEW_LIMIT)}건만 보입니다. 내보낸 파일에는 {n(check.included.length)}건이 모두
                들어갑니다.
              </p>
            ) : null}
          </>
        )}
      </section>

      <section
        className="stage-section report-export"
        id="report-export"
        tabIndex={-1}
        aria-labelledby="report-export-title"
      >
        <h3 id="report-export-title">내보내기</h3>
        <div className="report-export-primary">
          <ReasonButton
            className="button primary roomy"
            reason={report.disabledReason}
            data-testid="report-export-primary"
            onClick={() => void openDialog.run()}
          >
            보고서 내보내기…
          </ReasonButton>
          <p className="report-export-audience">{EXPORT_ACTIONS[0]?.audience}</p>
        </div>
        <h4 className="report-export-more">다른 형식</h4>
        <ul className="report-export-list">
          {EXPORT_ACTIONS.filter((action) => action.kind !== "case-report").map((action) => (
            <li key={action.commandId}>
              <CommandButton command={action.commandId} label={`${action.label} 내보내기`} showReason />
              <p className="report-export-audience">{action.audience}</p>
            </li>
          ))}
        </ul>
        <h4 className="report-export-more">이 세션에서 내보낸 파일</h4>
        {mine.length === 0 ? (
          <p className="analysis-desc">아직 없습니다.</p>
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

      <details
        className="stage-section report-outputs"
        id="report-outputs"
        tabIndex={-1}
        open={outputsOpen}
        onToggle={(event) => setOutputsOpen(event.currentTarget.open)}
      >
        <summary>처리 결과 파일{outputCount !== undefined ? ` (${n(outputCount)})` : ""}</summary>
        <p className="analysis-desc">
          이 런이 만든 산출 파일(아티팩트 JSON·보고 원본 등)입니다. 보고서가 아닙니다.
        </p>
        {outputsOpen ? (
          <div className="stage-report-grid">
            <DataGrid />
          </div>
        ) : null}
      </details>
    </section>
  );
}
