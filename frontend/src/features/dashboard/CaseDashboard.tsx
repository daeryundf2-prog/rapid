/**
 * 접수 dashboard (plan §9 X1/X9/X10/X18, AXIOM 케이스 대시보드 §2a; r7 examiner-first redesign).
 * A sticky status strip (런 이름 · 상태 · 모드 · 시작→완료 · 총 소요 · 단계 진행 · 처리 요약 보기) over
 * a 12-column band grid of 9 cards in examiner order — 처리 상태 · 증거 / 아티팩트 범주 · 처리
 * 경고·제한 사항 / 사건 정보 · 키워드 일치 · 시작할 곳 / 노트·메모 · 검토·보고서 — with equal-height
 * cards per band. A container query (≥ 1100 px pane) switches the band grid on; a narrower pane
 * gets one column. Mounted in the grid slot when the route's collection is "intake"
 * (app/IntakePane.tsx).
 */

import { useLayoutEffect, useMemo, useRef } from "react";
import type { CollectionId, ReviewStatus } from "../../contracts/collection";
import type { IconName } from "../../icons";
import { useRoute } from "../../state/hooks";
import { isRunActive } from "../../state/slices/runs";
import { useRunCaseLink } from "../case/caseLink";
import { useSearchState } from "../case/searchState";
import { Card, CardEmpty, CardError, type CardSpan, useCardLayout } from "./Card";
import {
  CategoryCard,
  ExportsCard,
  KeywordCard,
  ReviewCard,
  StartCard,
  StatusCard,
  StatusStrip,
} from "./cards";
import {
  CaseInfoCard,
  EvidenceCard,
  NoCaseLink,
  NotesCard,
  useCaseIntakeData,
  WarningsCard,
  warningCounts,
  warningCountsText,
} from "./caseCards";
import { disclosureItems, runWarnings } from "./disclosures";
import { categoryBars, keywordRows, reviewSummary, stageRows } from "./model";
import { useDashboardData } from "./useDashboardData";
import "./dashboard.css";

/** Examiner order (r7): status first, then what came in, what went wrong, the case, the notes. */
export const CARD_IDS = [
  "status",
  "evidence",
  "categories",
  "warnings",
  "case-info",
  "keywords",
  "start",
  "notes",
  "review",
] as const;
export type CardId = (typeof CARD_IDS)[number];

/** Column span per card in the 12-column band grid (rows: 8+4 · 6+6 · 4+4+4 · 8+4). */
export const CARD_SPANS: Record<CardId, CardSpan> = {
  status: 8,
  evidence: 4,
  categories: 6,
  warnings: 6,
  "case-info": 4,
  keywords: 4,
  start: 4,
  notes: 8,
  review: 4,
};

const CARD_META: Record<CardId, { title: string; icon: IconName }> = {
  status: { title: "처리 상태", icon: "clock" },
  evidence: { title: "증거", icon: "hard-drive" },
  categories: { title: "아티팩트 범주", icon: "layers" },
  warnings: { title: "처리 경고·제한 사항", icon: "alert" },
  "case-info": { title: "사건 정보", icon: "inbox" },
  keywords: { title: "키워드 일치", icon: "search" },
  start: { title: "시작할 곳", icon: "arrow-right" },
  notes: { title: "노트·메모", icon: "message" },
  review: { title: "검토·보고서", icon: "tag" },
};

const WAIT_FOR_RUN = "런이 완료되면 표시됩니다.";

/** After 처리 설정 보기: scroll to and focus the 처리 page's settings section once it renders. */
function focusProcessSettings(tries = 40): void {
  const target = document.getElementById("process-settings");
  if (target) {
    target.scrollIntoView?.({ block: "start" });
    if (!target.hasAttribute("tabindex")) target.setAttribute("tabindex", "-1");
    target.focus({ preventScroll: true });
    return;
  }
  if (tries > 0) window.setTimeout(() => focusProcessSettings(tries - 1), 100);
}

/** One card's own skeleton while its data loads (C-I1): the card is there, its body fills in. */
function CardSkeleton() {
  return (
    <div className="dash-skeleton" aria-hidden="true" data-testid="card-skeleton">
      <span className="skeleton" style={{ width: "60%" }} />
      <span className="skeleton" style={{ width: "30%" }} />
      <span className="skeleton" style={{ width: "45%" }} />
    </div>
  );
}

/** "카드 N/M" while the intake cards load (C-I1: a 12 s first load was skeletons only, no progress). */
function CardProgress({ ready, total }: { ready: number; total: number }) {
  if (total === 0 || ready >= total) return null;
  return (
    <p className="dash-card-progress" data-testid="dash-card-progress">
      <progress max={total} value={ready} aria-label="접수 카드 불러오기" /> 카드 {ready}/{total} 준비됨
    </p>
  );
}

/** Keeps `--dash-head-h` on the scroller equal to the sticky head's height (card heads stick below it). */
function useStickyHeadHeight(ready: boolean) {
  const scroller = useRef<HTMLDivElement>(null);
  const head = useRef<HTMLDivElement>(null);
  // biome-ignore lint/correctness/useExhaustiveDependencies: re-run once the loaded head mounts (the skeleton render has no head)
  useLayoutEffect(() => {
    const root = scroller.current;
    const el = head.current;
    if (!root || !el) return;
    const sync = () =>
      root.style.setProperty("--dash-head-h", `${Math.ceil(el.getBoundingClientRect().height)}px`);
    sync();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(sync);
    observer.observe(el);
    return () => observer.disconnect();
  }, [ready]);
  return { scroller, head };
}

export function CaseDashboard({ runId }: { runId: string }) {
  const { openCollection } = useRoute();
  const applySaved = useSearchState((s) => s.applySaved);
  const data = useDashboardData(runId);
  const { layout, setCollapsed, setHidden, showAll } = useCardLayout();
  const { detail, completed, summary, tree, review, saved, dashboard, notes, issues } = data;
  const snapshot = useRunCaseLink(runId);
  const runFinished = Boolean(detail.data) && !isRunActive(detail.data);
  const intake = useCaseIntakeData(runId, snapshot.data, runFinished);
  const caseDetail = intake.detail.data;
  const { scroller, head } = useStickyHeadHeight(Boolean(detail.data));

  const counts = summary.data?.summary?.counts;
  const categories = useMemo(() => categoryBars(tree.data), [tree.data]);
  const reviewRows = useMemo(() => reviewSummary(review.data), [review.data]);
  const keywords = useMemo(
    () => keywordRows(dashboard.data?.profile.keywords ?? [], saved.data ?? []),
    [dashboard.data, saved.data],
  );

  if (detail.isPending) {
    // The final card shells in their final order and spans, skeleton lines inside (review #11):
    // nothing jumps when the data arrives.
    const shells = CARD_IDS.filter((id) => !layout.hidden.includes(id));
    return (
      <div className="dash" data-testid="intake-pane" aria-busy="true">
        <CardProgress ready={0} total={shells.length} />
        <div className="dash-grid">
          {shells.map((id, index) => (
            <section
              key={id}
              className="dash-card"
              aria-label={CARD_META[id].title}
              data-span={CARD_SPANS[id]}
            >
              <div className="dash-card-head">
                {/* Not a heading yet: the loaded card's own h2 replaces it (one outline). */}
                <span className="dash-card-title-static">{CARD_META[id].title}</span>
              </div>
              <div className="dash-card-body">
                {index === 0 ? <p className="visually-hidden">케이스 정보를 불러오는 중…</p> : null}
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
  const stages = stageRows(run.progress);
  const go = (
    collection: CollectionId,
    options: { kind?: string; status?: ReviewStatus; category?: string; q?: string } = {},
  ) => openCollection(collection, options);

  const cardProps = (id: CardId, refresh?: () => void) => ({
    id,
    title: CARD_META[id].title,
    icon: CARD_META[id].icon,
    span: CARD_SPANS[id],
    collapsed: layout.collapsed.includes(id),
    onCollapsedChange: (value: boolean) => setCollapsed(id, value),
    onHide: () => setHidden(id, true),
    onRefresh: refresh,
  });
  const visible = (id: CardId) => !layout.hidden.includes(id);
  const hiddenCount = CARD_IDS.filter((id) => layout.hidden.includes(id)).length;

  const disclosures = completed && summary.data ? disclosureItems(summary.data) : [];
  const warnings = completed && summary.data ? runWarnings(summary.data) : [];
  const warnCounts =
    runFinished && (intake.problems.data || summary.data)
      ? warningCounts(intake.problems.data, disclosures, warnings)
      : null;
  const crumb = caseDetail ? `${caseDetail.case_number} › ${intake.evidenceNumber || "—"}` : null;
  const outputDir = String(run.request?.output_dir ?? snapshot.data?.snapshot.request?.output_dir ?? "");
  const caseLoading = snapshot.isPending || Boolean(intake.caseId && intake.detail.isPending);
  // Which cards have their data (or know they wait for the run): the "카드 N/M" line.
  const cardReady: Record<CardId, boolean> = {
    status: true,
    evidence: !(caseLoading || (dashboard.isPending && !caseDetail)),
    categories: !completed || !tree.isPending,
    warnings: !runFinished || !(intake.problems.isPending || (completed && summary.isPending)),
    "case-info": !caseLoading,
    keywords: !completed || !dashboard.isPending,
    start: true,
    notes: !(notes.isPending || snapshot.isPending),
    review: !completed || !(review.isPending || dashboard.isPending),
  };
  const shownCards = CARD_IDS.filter((id) => !layout.hidden.includes(id));
  const readyCards = shownCards.filter((id) => cardReady[id]).length;

  return (
    <div className="dash" data-testid="intake-pane" ref={scroller}>
      <div className="dash-head" ref={head}>
        <StatusStrip
          run={run}
          stages={stages}
          crumb={crumb}
          onOpenSummary={() => {
            if (completed) go("outputs");
          }}
          onOpenSettings={() => {
            // L1's anchor on the 처리 page: land on the run's settings, not the top of the page.
            go("process");
            focusProcessSettings();
          }}
        >
          {hiddenCount ? (
            <button type="button" className="button ghost" onClick={showAll}>
              숨긴 카드 {hiddenCount}개 다시 표시
            </button>
          ) : null}
        </StatusStrip>
        <CardProgress ready={readyCards} total={shownCards.length} />
      </div>

      <div className="dash-grid">
        {visible("status") ? (
          <Card {...cardProps("status", () => void detail.refetch())}>
            <StatusCard
              run={run}
              stages={stages}
              counts={counts}
              outputDir={outputDir}
              issues={issues.data?.rows}
            />
          </Card>
        ) : null}

        {visible("evidence") ? (
          <Card
            {...cardProps("evidence", () => {
              void dashboard.refetch();
              void intake.detail.refetch();
            })}
            meta={caseDetail ? `증거 ${caseDetail.evidence_count} · 런 ${caseDetail.run_count}` : undefined}
          >
            {caseLoading || (dashboard.isPending && !caseDetail) ? (
              <CardSkeleton />
            ) : intake.caseId && (intake.detail.isError || !caseDetail) ? (
              <CardError error={intake.detail.error} />
            ) : !caseDetail && (dashboard.isError || !dashboard.data) ? (
              <CardError error={dashboard.error} />
            ) : (
              <EvidenceCard
                detail={caseDetail ?? null}
                source={dashboard.data?.evidence_source}
                counts={counts}
                currentRunId={runId}
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
              <CardSkeleton />
            ) : tree.isError ? (
              <CardError error={tree.error} />
            ) : (
              <CategoryCard
                bars={categories.bars}
                total={categories.total}
                onOpenCategory={(category) => go("artifacts", { category })}
              />
            )}
          </Card>
        ) : null}

        {visible("warnings") ? (
          <Card
            {...cardProps("warnings", () => {
              void intake.problems.refetch();
              void summary.refetch();
            })}
            meta={warnCounts ? warningCountsText(warnCounts) : undefined}
          >
            {!runFinished ? (
              <CardEmpty title="처리 경고·제한 사항">{WAIT_FOR_RUN}</CardEmpty>
            ) : intake.problems.isPending || (completed && summary.isPending) ? (
              <CardSkeleton />
            ) : intake.problems.isError && !summary.data ? (
              <CardError error={intake.problems.error} />
            ) : (
              <WarningsCard
                runId={runId}
                problems={intake.problems.data}
                items={disclosures}
                warnings={warnings}
              />
            )}
          </Card>
        ) : null}

        {visible("case-info") ? (
          <Card
            {...cardProps("case-info", () => {
              void snapshot.refetch();
              void intake.detail.refetch();
            })}
            meta={caseDetail ? caseDetail.case_number : snapshot.data ? "케이스 없음" : undefined}
          >
            {caseLoading ? (
              <CardSkeleton />
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

        {visible("keywords") ? (
          <Card {...cardProps("keywords", () => void saved.refetch())}>
            {!completed ? (
              <CardEmpty title="키워드 일치">{WAIT_FOR_RUN}</CardEmpty>
            ) : dashboard.isPending ? (
              <CardSkeleton />
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

        {visible("start") ? (
          <Card {...cardProps("start")}>
            <StartCard onGo={(target) => go(target)} />
          </Card>
        ) : null}

        {visible("notes") ? (
          <Card
            {...cardProps("notes", () => {
              void notes.refetch();
              void intake.notes.refetch();
            })}
            meta={intake.notes.data ? `메모 ${intake.notes.data.count}건` : undefined}
          >
            {notes.isPending || snapshot.isPending ? (
              <CardSkeleton />
            ) : (
              <NotesCard
                runId={runId}
                caseId={intake.caseId}
                caseExaminer={caseDetail?.examiner ?? ""}
                caseNotes={intake.notes.data}
                caseNotesState={
                  !intake.caseId
                    ? "none"
                    : intake.notes.isPending
                      ? "loading"
                      : intake.notes.isError
                        ? "error"
                        : "ready"
                }
                runNotes={notes.data}
              />
            )}
          </Card>
        ) : null}

        {visible("review") ? (
          <Card
            {...cardProps("review", () => {
              void review.refetch();
              void dashboard.refetch();
            })}
            meta={review.data ? `표시 ${reviewRows.total.toLocaleString("ko-KR")}건` : undefined}
          >
            {!completed ? (
              <CardEmpty title="검토·보고서">{WAIT_FOR_RUN}</CardEmpty>
            ) : review.isPending || dashboard.isPending ? (
              <CardSkeleton />
            ) : (
              <div className="dash-review">
                {review.isError ? (
                  <CardError error={review.error} />
                ) : (
                  <ReviewCard rows={reviewRows.rows} onOpenStatus={(status) => go("review", { status })} />
                )}
                {dashboard.isError || !dashboard.data ? (
                  <CardError error={dashboard.error} />
                ) : (
                  <ExportsCard entries={dashboard.data.exports} />
                )}
              </div>
            )}
          </Card>
        ) : null}
      </div>
    </div>
  );
}
