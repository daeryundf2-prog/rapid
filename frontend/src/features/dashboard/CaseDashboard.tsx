/**
 * 접수 dashboard (plan §9 X1/X9/X10/X18, AXIOM 케이스 대시보드 §2a): a card grid
 * — 3 columns from 1200 px, 1 column below — replacing the single-column
 * intake summary. Mounted in the grid slot when the route's collection is
 * "intake" (app/IntakePane.tsx).
 */

import { useMemo } from "react";
import { runDisplayName } from "../../app/collections";
import { StatusBadge } from "../../components/Badge";
import type { CollectionId, ReviewStatus } from "../../contracts/collection";
import type { IconName } from "../../icons";
import { useRoute } from "../../state/hooks";
import { useSearchState } from "../case/searchState";
import { Card, CardEmpty, CardError, CardLoading, useCardLayout } from "./Card";
import {
  CaseNotesCard,
  CategoryCard,
  EvidenceCard,
  ExportsCard,
  KeywordCard,
  ProcessingCard,
  ReviewCard,
  StartCard,
} from "./cards";
import { categoryBars, keywordRows, reviewSummary, stageRows } from "./model";
import { useDashboardData } from "./useDashboardData";
import "./dashboard.css";

export const CARD_IDS = [
  "notes",
  "evidence",
  "categories",
  "processing",
  "review",
  "keywords",
  "exports",
  "start",
] as const;
export type CardId = (typeof CARD_IDS)[number];

const CARD_META: Record<CardId, { title: string; icon: IconName }> = {
  notes: { title: "케이스 요약 노트", icon: "file-text" },
  evidence: { title: "증거 소스", icon: "hard-drive" },
  categories: { title: "아티팩트 범주", icon: "layers" },
  processing: { title: "케이스 처리 세부", icon: "clock" },
  review: { title: "태그 및 리뷰 상태", icon: "tag" },
  keywords: { title: "키워드 일치", icon: "search" },
  exports: { title: "내보내기/보고서 이력", icon: "download" },
  start: { title: "시작할 곳", icon: "arrow-right" },
};

const WAIT_FOR_RUN = "런이 완료되면 표시됩니다.";

export function CaseDashboard({ runId }: { runId: string }) {
  const { openCollection } = useRoute();
  const applySaved = useSearchState((s) => s.applySaved);
  const data = useDashboardData(runId);
  const { layout, setCollapsed, setHidden, showAll } = useCardLayout();
  const { detail, completed, summary, tree, review, saved, dashboard, notes, issues } = data;

  const counts = summary.data?.summary?.counts;
  const categories = useMemo(() => categoryBars(tree.data), [tree.data]);
  const reviewRows = useMemo(() => reviewSummary(review.data), [review.data]);
  const keywords = useMemo(
    () => keywordRows(dashboard.data?.profile.keywords ?? [], saved.data ?? []),
    [dashboard.data, saved.data],
  );

  if (detail.isPending) {
    // The final card shells in their final order, skeleton lines inside (review #11): nothing
    // jumps when the data arrives.
    const shells = CARD_IDS.filter((id) => !layout.hidden.includes(id));
    return (
      <div className="dash" data-testid="intake-pane" aria-busy="true">
        <div className="dash-grid">
          {shells.map((id, index) => (
            <section key={id} className="dash-card" aria-label={CARD_META[id].title}>
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

  return (
    <div className="dash" data-testid="intake-pane">
      <div className="dash-head">
        <h1>{runDisplayName(run)}</h1>
        <StatusBadge status={String(run.status)} />
        {hiddenCount ? (
          <button type="button" className="button ghost dash-head-action" onClick={showAll}>
            숨긴 카드 {hiddenCount}개 다시 표시
          </button>
        ) : null}
      </div>

      <div className="dash-grid">
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
