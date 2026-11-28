/**
 * 접수 dashboard = 사건 개요 (design overhaul F6/F7/F9; plan §9 X1/X9/X10/X18): statuses with
 * their subject, 먼저 할 일, the case's key numbers and activity by date on top, then the detail
 * cards in balanced columns (on a first visit only the case intake cards are open: case info,
 * evidence, settings summary, problems, case memo). Mounted in the grid slot when the route's
 * collection is "intake" (app/IntakePane.tsx).
 */

import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { getReviewMap } from "../../api/caseDb";
import { runDisplayName } from "../../app/collections";
import { WaitPanel } from "../../components/WaitPanel";
import type { CollectionId, ReviewStatus } from "../../contracts/collection";
import type { IconName } from "../../icons";
import { useRoute } from "../../state/hooks";
import { isRunActive } from "../../state/slices/runs";
import { useRunCaseLink } from "../case/caseLink";
import { sealState } from "../case/integrity";
import { useSearchState } from "../case/searchState";
import { reviewMapKey } from "../grid/reviewMap";
import { Card, CardEmpty, CardError, CardLoading, useCardLayout } from "./Card";
import {
  CaseNotesCard,
  CategoryCard,
  DisclosuresCard,
  EvidenceCard,
  ExportsCard,
  KeywordCard,
  ProcessingCard,
  ReviewCard,
  StartCard,
} from "./cards";
import {
  CaseEvidenceCard,
  CaseInfoCard,
  CaseMemoCard,
  NoCaseLink,
  ProblemsCard,
  SnapshotCard,
  useCaseIntakeData,
} from "./caseCards";
import { disclosureItems, runWarnings } from "./disclosures";
import { categoryBars, keywordRows, reviewSummary, stageRows } from "./model";
import { ActivityByDate, DashStatus, OverviewFigures, TodoList } from "./Overview";
import { type FigureId, isEmptyRun, overviewFigures, type TodoItem, todoItems } from "./overviewModel";
import { useDashboardData } from "./useDashboardData";
import "./dashboard.css";

export const CARD_IDS = [
  // Case intake (AXIOM adoption E1); the first five stay open on a first visit (case identity
  // first: reviewers and report recipients check whose case this is before anything else).
  "case-info",
  "case-evidence",
  "snapshot",
  "problems",
  "case-memo",
  "notes",
  "evidence",
  "categories",
  "processing",
  "disclosures",
  "review",
  "keywords",
  "exports",
  "start",
] as const;
export type CardId = (typeof CARD_IDS)[number];

/** Collapsed until the examiner opens them (the overview above already carries their headline). */
export const DEFAULT_COLLAPSED_CARDS: readonly CardId[] = CARD_IDS.slice(5);

const CARD_META: Record<CardId, { title: string; icon: IconName }> = {
  "case-info": { title: "사건 정보", icon: "inbox" },
  "case-evidence": { title: "증거 목록", icon: "hard-drive" },
  snapshot: { title: "처리 설정 스냅샷", icon: "settings" },
  problems: { title: "처리 문제", icon: "alert" },
  "case-memo": { title: "케이스 메모", icon: "message" },
  notes: { title: "케이스 요약 노트", icon: "file-text" },
  evidence: { title: "증거 소스", icon: "hard-drive" },
  categories: { title: "아티팩트 범주", icon: "layers" },
  processing: { title: "케이스 처리 세부", icon: "clock" },
  disclosures: { title: "공개 사항", icon: "alert" },
  review: { title: "태그 및 리뷰 상태", icon: "tag" },
  keywords: { title: "키워드 일치", icon: "search" },
  exports: { title: "내보내기/보고서 이력", icon: "download" },
  start: { title: "시작할 곳", icon: "arrow-right" },
};

const WAIT_FOR_RUN = "런이 완료되면 표시됩니다.";

const FIGURE_COLLECTION: Record<Exclude<FigureId, "marks">, CollectionId> = {
  timeline: "timeline",
  files: "files",
  artifacts: "artifacts",
  indicators: "indicators",
};

export function CaseDashboard({ runId }: { runId: string }) {
  const { openCollection, navigate } = useRoute();
  const applySaved = useSearchState((s) => s.applySaved);
  const data = useDashboardData(runId);
  const { layout, setCollapsed, setHidden, showAll } = useCardLayout(DEFAULT_COLLAPSED_CARDS);
  const { detail, completed, summary, tree, review, saved, dashboard, notes, issues } = data;
  const snapshot = useRunCaseLink(runId);
  const runFinished = Boolean(detail.data) && !isRunActive(detail.data);
  const intake = useCaseIntakeData(runId, snapshot.data, runFinished);
  const caseDetail = intake.detail.data;
  // The raw marks (not the locator map): marks without a run-output locator still count.
  const marks = useQuery({
    queryKey: [...reviewMapKey(runId), "marks"],
    queryFn: ({ signal }) => getReviewMap(runId, signal).then((payload) => payload.marks ?? []),
    enabled: completed,
    retry: false,
  });

  const counts = summary.data?.summary?.counts;
  const categories = useMemo(() => categoryBars(tree.data), [tree.data]);
  const reviewRows = useMemo(() => reviewSummary(review.data), [review.data]);
  const keywords = useMemo(
    () => keywordRows(dashboard.data?.profile.keywords ?? [], saved.data ?? []),
    [dashboard.data, saved.data],
  );
  const seal = useMemo(() => (caseDetail ? sealState(caseDetail.evidence) : null), [caseDetail]);
  const todo = useMemo(
    () =>
      todoItems({
        seal,
        problems: intake.problems.data,
        indicators: counts?.indicators,
        marks: marks.data,
      }),
    [seal, intake.problems.data, counts?.indicators, marks.data],
  );
  const figures = useMemo(() => overviewFigures(counts, review.data), [counts, review.data]);

  if (detail.isPending) {
    // The final card shells in their final order, skeleton lines inside (review #11): nothing
    // jumps when the data arrives.
    const shells = CARD_IDS.filter((id) => !layout.hidden.includes(id));
    return (
      <div className="dash" data-testid="intake-pane" aria-busy="true">
        <WaitPanel className="floating dash-wait" label="케이스 여는 중…" testId="dash-wait" />
        <div className="dash-grid">
          {shells.map((id) => (
            <section key={id} className="dash-card" aria-label={CARD_META[id].title}>
              <div className="dash-card-head">
                {/* Not a heading yet: the loaded card's own h2 replaces it (one outline). */}
                <span className="dash-card-title-static">{CARD_META[id].title}</span>
              </div>
              <div className="dash-card-body">
                <div className="dash-skeleton" aria-hidden="true">
                  <span className="skeleton" style={{ width: "60%" }} />
                  <span className="skeleton" style={{ width: "30%" }} />
                  <span className="skeleton" style={{ width: "45%" }} />
                </div>
              </div>
            </section>
          ))}
        </div>
      </div>
    );
  }
  if (detail.isError || !detail.data) {
    return (
      <div className="dash" data-testid="intake-pane">
        <p className="error-banner">접수 정보를 불러오지 못했습니다: {String(detail.error?.message ?? "")}</p>
      </div>
    );
  }

  const run = { ...detail.data, run_id: detail.data.run_id ?? runId };
  const go = (
    collection: CollectionId,
    options: { kind?: string; status?: ReviewStatus; category?: string; q?: string } = {},
  ) => openCollection(collection, options);

  const cardProps = (id: CardId, refresh?: () => void) => ({
    id,
    title: CARD_META[id].title,
    icon: CARD_META[id].icon,
    collapsed: layout.collapsed.includes(id),
    onCollapsedChange: (value: boolean) => setCollapsed(id, value),
    onHide: () => setHidden(id, true),
    onRefresh: refresh,
  });
  const visible = (id: CardId) => !layout.hidden.includes(id);
  const hiddenCount = CARD_IDS.filter((id) => layout.hidden.includes(id)).length;
  /** Opens (and un-hides) a card, scrolls to it and puts focus on its toggle. */
  const reveal = (id: CardId) => {
    setHidden(id, false);
    setCollapsed(id, false);
    requestAnimationFrame(() => {
      const section = document.querySelector<HTMLElement>(`[data-card="${id}"]`);
      section?.scrollIntoView?.({ block: "start" });
      section?.querySelector<HTMLElement>(".dash-card-toggle")?.focus({ preventScroll: true });
    });
  };
  const onTodo = (item: TodoItem) => {
    if (item.id === "hash") reveal("case-evidence");
    else if (item.id === "problems") reveal("problems");
    else if (item.id === "indicators") go("indicators");
    // 관련 있음 AND 보고서 미포함: the board's 보고서 column filter (cf=report:미포함, PR ⑤ board column).
    else
      navigate({
        runId,
        collection: "review",
        status: "relevant",
        cf: [{ col: "report", op: ":", value: "미포함" }],
      });
  };
  const known = (query: { data?: unknown; isError: boolean }) => query.data !== undefined || query.isError;
  const todoReady =
    runFinished &&
    known(intake.problems) &&
    (!completed || (known(marks) && known(summary))) &&
    known(snapshot) &&
    (!intake.caseId || known(intake.detail));

  return (
    <div className="dash" data-testid="intake-pane">
      <div className="dash-head">
        <h1>{runDisplayName(run)}</h1>
        <DashStatus run={run} caseDetail={caseDetail} />
        {caseDetail ? (
          <p className="dash-crumb" data-testid="case-crumb">
            <span className="visually-hidden">케이스 › 증거 › 런: </span>
            {caseDetail.case_number} › {intake.evidenceNumber || "—"} › {runId.slice(0, 8)}
          </p>
        ) : null}
        {hiddenCount ? (
          <button type="button" className="button ghost dash-head-action" onClick={showAll}>
            숨긴 카드 {hiddenCount}개 다시 표시
          </button>
        ) : null}
      </div>

      <TodoList
        items={todo}
        ready={todoReady}
        waiting={!runFinished}
        seal={seal}
        caseId={intake.caseId}
        onAction={onTodo}
      />

      <div className="dash-top">
        <OverviewFigures
          run={run}
          figures={completed ? figures : []}
          empty={completed && isEmptyRun(counts)}
          review={review.data}
          error={summary.isError ? String(summary.error?.message ?? "") : null}
          onOpen={(figure, status) =>
            figure === "marks" ? go("review", status ? { status } : {}) : go(FIGURE_COLLECTION[figure])
          }
          onShowProblems={() => reveal("problems")}
        />
        <ActivityByDate runId={runId} completed={completed} events={counts?.timeline_events} />
      </div>

      <div className="dash-grid">
        {visible("case-info") ? (
          <Card
            {...cardProps("case-info", () => {
              void snapshot.refetch();
              void intake.detail.refetch();
            })}
            meta={caseDetail ? caseDetail.case_number : snapshot.data ? "케이스 없음" : undefined}
          >
            {snapshot.isPending || (intake.caseId && intake.detail.isPending) ? (
              <CardLoading />
            ) : snapshot.isError ? (
              <CardError error={snapshot.error} />
            ) : !intake.caseId ? (
              <NoCaseLink />
            ) : intake.detail.isError || !caseDetail ? (
              <CardError error={intake.detail.error} />
            ) : (
              <CaseInfoCard detail={caseDetail} />
            )}
          </Card>
        ) : null}

        {visible("case-evidence") ? (
          <Card
            {...cardProps("case-evidence", () => void intake.detail.refetch())}
            meta={
              caseDetail ? `증거 ${caseDetail.evidence_count}건, 런 ${caseDetail.run_count}개` : undefined
            }
          >
            {snapshot.isPending || (intake.caseId && intake.detail.isPending) ? (
              <CardLoading />
            ) : !intake.caseId ? (
              <CardEmpty title="증거 목록">
                케이스에 연결하면 케이스의 증거와 증거별 런이 표시됩니다.
              </CardEmpty>
            ) : intake.detail.isError || !caseDetail ? (
              <CardError error={intake.detail.error} />
            ) : (
              <CaseEvidenceCard detail={caseDetail} currentRunId={runId} />
            )}
          </Card>
        ) : null}

        {visible("snapshot") ? (
          <Card {...cardProps("snapshot", () => void snapshot.refetch())}>
            {snapshot.isPending ? (
              <CardLoading />
            ) : snapshot.isError || !snapshot.data ? (
              <CardError error={snapshot.error} />
            ) : (
              <SnapshotCard snapshot={snapshot.data} />
            )}
          </Card>
        ) : null}

        {visible("problems") ? (
          <Card
            {...cardProps("problems", () => void intake.problems.refetch())}
            meta={
              intake.problems.data ? `${intake.problems.data.total.toLocaleString("ko-KR")}건` : undefined
            }
          >
            {!runFinished ? (
              <CardEmpty title="처리 문제">{WAIT_FOR_RUN}</CardEmpty>
            ) : intake.problems.isPending ? (
              <CardLoading />
            ) : intake.problems.isError || !intake.problems.data ? (
              <CardError error={intake.problems.error} />
            ) : (
              <ProblemsCard runId={runId} problems={intake.problems.data} />
            )}
          </Card>
        ) : null}

        {visible("case-memo") ? (
          <Card
            {...cardProps("case-memo", () => void intake.notes.refetch())}
            meta={intake.notes.data ? `${intake.notes.data.count}건` : undefined}
          >
            {snapshot.isPending || (intake.caseId && intake.notes.isPending) ? (
              <CardLoading />
            ) : !intake.caseId ? (
              <CardEmpty title="케이스 메모">
                케이스에 연결하면 작성자·시각이 남는 케이스 메모를 쓸 수 있습니다.
              </CardEmpty>
            ) : intake.notes.isError || !intake.notes.data ? (
              <CardError error={intake.notes.error} />
            ) : (
              <CaseMemoCard
                caseId={intake.caseId}
                examiner={caseDetail?.examiner ?? ""}
                notes={intake.notes.data}
              />
            )}
          </Card>
        ) : null}

        {visible("notes") ? (
          <Card {...cardProps("notes", () => void notes.refetch())}>
            {notes.isPending ? (
              <CardLoading />
            ) : notes.isError ? (
              <CardError error={notes.error} />
            ) : (
              <CaseNotesCard runId={runId} notes={notes.data} />
            )}
          </Card>
        ) : null}

        {visible("evidence") ? (
          <Card {...cardProps("evidence", () => void dashboard.refetch())}>
            {dashboard.isPending ? (
              <CardLoading />
            ) : dashboard.isError || !dashboard.data ? (
              <CardError error={dashboard.error} />
            ) : (
              <EvidenceCard
                source={dashboard.data.evidence_source}
                counts={counts}
                onOpenFiles={() => go("files")}
              />
            )}
          </Card>
        ) : null}

        {visible("categories") ? (
          <Card
            {...cardProps("categories", () => void tree.refetch())}
            meta={completed && tree.data ? `전체 ${categories.total.toLocaleString("ko-KR")}건` : undefined}
          >
            {!completed ? (
              <CardEmpty title="아티팩트 범주">{WAIT_FOR_RUN}</CardEmpty>
            ) : tree.isPending ? (
              <CardLoading />
            ) : tree.isError ? (
              <CardError error={tree.error} />
            ) : (
              <CategoryCard
                bars={categories.bars}
                total={categories.total}
                sourceName={dashboard.data?.evidence_source.name}
                onOpenCategory={(category) => go("artifacts", { category })}
              />
            )}
          </Card>
        ) : null}

        {visible("processing") ? (
          <Card {...cardProps("processing", () => void detail.refetch())}>
            <ProcessingCard
              run={run}
              stages={stageRows(run.progress)}
              issues={issues.data?.rows}
              onOpenOutputs={() => {
                if (completed) go("outputs");
              }}
            />
          </Card>
        ) : null}

        {visible("disclosures") ? (
          <Card
            {...cardProps("disclosures", () => void summary.refetch())}
            meta={
              completed && summary.data
                ? (() => {
                    const warn = disclosureItems(summary.data).filter((item) => item.tone === "warn").length;
                    return warn ? `확인 필요 ${warn}` : undefined;
                  })()
                : undefined
            }
          >
            {!completed ? (
              <CardEmpty title="공개 사항">{WAIT_FOR_RUN}</CardEmpty>
            ) : summary.isPending ? (
              <CardLoading />
            ) : summary.isError ? (
              <CardError error={summary.error} />
            ) : (
              <DisclosuresCard items={disclosureItems(summary.data)} warnings={runWarnings(summary.data)} />
            )}
          </Card>
        ) : null}

        {visible("review") ? (
          <Card
            {...cardProps("review", () => void review.refetch())}
            meta={review.data ? `표시 ${reviewRows.total.toLocaleString("ko-KR")}건` : undefined}
          >
            {!completed ? (
              <CardEmpty title="리뷰 상태">{WAIT_FOR_RUN}</CardEmpty>
            ) : review.isPending ? (
              <CardLoading />
            ) : review.isError ? (
              <CardError error={review.error} />
            ) : (
              <ReviewCard rows={reviewRows.rows} onOpenStatus={(status) => go("review", { status })} />
            )}
          </Card>
        ) : null}

        {visible("keywords") ? (
          <Card {...cardProps("keywords", () => void saved.refetch())}>
            {!completed ? (
              <CardEmpty title="키워드 일치">{WAIT_FOR_RUN}</CardEmpty>
            ) : dashboard.isPending ? (
              <CardLoading />
            ) : (
              <KeywordCard
                runId={runId}
                rows={keywords}
                enabled={completed && !layout.collapsed.includes("keywords")}
                onOpen={(row) => {
                  if (row.savedSearch) applySaved(row.savedSearch);
                  go("search", { q: row.query });
                }}
              />
            )}
          </Card>
        ) : null}

        {visible("exports") ? (
          <Card {...cardProps("exports", () => void dashboard.refetch())}>
            {!completed ? (
              <CardEmpty title="내보내기 이력">{WAIT_FOR_RUN}</CardEmpty>
            ) : dashboard.isPending ? (
              <CardLoading />
            ) : dashboard.isError || !dashboard.data ? (
              <CardError error={dashboard.error} />
            ) : (
              <ExportsCard entries={dashboard.data.exports} />
            )}
          </Card>
        ) : null}

        {visible("start") ? (
          <Card {...cardProps("start")}>
            <StartCard onGo={(target) => go(target)} />
          </Card>
        ) : null}
      </div>
    </div>
  );
}
