/**
 * Pure data mapping behind the 접수 dashboard cards (plan §9 X1). Every card
 * reads one of these so the mapping is unit-tested without rendering.
 */

import type { ReviewCounts, SavedSearch } from "../../api/caseDb";
import type { ExportEntry } from "../../api/dashboard";
import type { CanonicalCounts, RunTree } from "../../api/runs";
import type { ReviewStatus } from "../../contracts/collection";
import { runEvidenceTimezone } from "../../state/hooks";
import { currentRun } from "../../state/slices/runs";
import { useAppStore } from "../../state/store";
import { formatRunTime } from "../../utils/time";
import { type ArtifactCategory, groupByCategory } from "../tree/categories";
import { artifactKindNodes } from "../tree/model";

// --- stages -----------------------------------------------------------------

export interface ProgressLike {
  status?: string;
  stage?: string;
  stage_started_at?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  completed_stages?: Array<{ stage?: string; completed_at?: string }>;
}

export interface StageRow {
  stage: string;
  state: "done" | "running";
  startedAt: string | null;
  completedAt: string | null;
  /** ms; null when a bound is missing. */
  durationMs: number | null;
}

function ms(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

/** Completed stages with durations (previous completion → this completion) plus the running stage. */
export function stageRows(progress: ProgressLike | null | undefined, now = Date.now()): StageRow[] {
  if (!progress) return [];
  const rows: StageRow[] = [];
  let previous = progress.started_at ?? null;
  for (const entry of progress.completed_stages ?? []) {
    const start = ms(previous);
    const end = ms(entry.completed_at);
    rows.push({
      stage: entry.stage ?? "—",
      state: "done",
      startedAt: previous,
      completedAt: entry.completed_at ?? null,
      durationMs: start !== null && end !== null ? Math.max(0, end - start) : null,
    });
    previous = entry.completed_at ?? previous;
  }
  if (progress.stage && progress.status !== "completed" && progress.status !== "failed") {
    const start = ms(progress.stage_started_at ?? previous);
    rows.push({
      stage: progress.stage,
      state: "running",
      startedAt: progress.stage_started_at ?? previous,
      completedAt: null,
      durationMs: start !== null ? Math.max(0, now - start) : null,
    });
  }
  return rows;
}

export function formatDuration(value: number | null | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  if (value < 1000) return `${Math.round(value)}ms`;
  const s = value / 1000;
  if (s < 60) return `${s.toFixed(1)}초`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}분 ${Math.round(s % 60)}초`;
  return `${Math.floor(m / 60)}시간 ${m % 60}분`;
}

/** The display timezone right now (URL `tz=` > preference > evidence zone > browser), outside React. */
export function displayTimezoneNow(): string {
  const state = useAppStore.getState();
  return state.route.tz ?? state.timezone ?? runEvidenceTimezone(currentRun(state)) ?? "local";
}

/**
 * Times of the 접수 cards (C-G4): the one console format — "2026-10-17 20:18" in the display
 * timezone (`formatRunTime`), never the browser's `toLocaleString`; "—" when missing, the raw text
 * when unparseable.
 */
export function formatTime(value: string | null | undefined, tz: string = displayTimezoneNow()): string {
  if (!value) return "—";
  return formatRunTime(value, tz);
}

// --- artifact categories ----------------------------------------------------

export interface CategoryBar {
  category: ArtifactCategory;
  count: number;
  /** 0–1 of the largest bar. */
  ratio: number;
  kinds: string[];
}

/** Category totals for the bar chart, largest first (zero-count categories dropped). */
export function categoryBars(tree: RunTree | undefined): { bars: CategoryBar[]; total: number } {
  const groups = groupByCategory(
    artifactKindNodes(tree),
    (node) => node.kind ?? "",
    (node) => node.count,
  ).filter((group) => group.total > 0);
  const max = Math.max(0, ...groups.map((group) => group.total));
  const bars = groups
    .map((group) => ({
      category: group.category,
      count: group.total,
      ratio: max > 0 ? group.total / max : 0,
      kinds: group.items.map((node) => node.kind ?? ""),
    }))
    .sort((a, b) => b.count - a.count);
  return { bars, total: bars.reduce((sum, bar) => sum + bar.count, 0) };
}

// --- review status ----------------------------------------------------------

export interface ReviewSummaryRow {
  key: ReviewStatus | "bookmark";
  label: string;
  /** CSS custom property (S10 tokens) with a fallback colour. */
  color: string;
  count: number;
  status?: ReviewStatus;
}

export const REVIEW_ROWS: ReadonlyArray<Omit<ReviewSummaryRow, "count">> = [
  { key: "relevant", label: "관련 있음", color: "var(--status-relevant, #ef6b6b)", status: "relevant" },
  {
    key: "needs-review",
    label: "재검토",
    color: "var(--status-needs-review, #5aa8ff)",
    status: "needs-review",
  },
  { key: "excluded", label: "제외", color: "var(--status-excluded, #e8863a)", status: "excluded" },
  {
    key: "include-in-report",
    label: "보고서 포함",
    color: "var(--status-report, #a58bf0)",
    status: "include-in-report",
  },
  { key: "bookmark", label: "리뷰보드 항목(북마크)", color: "var(--status-bookmark, #3fb96f)" },
];

export function reviewSummary(review: ReviewCounts | undefined): { rows: ReviewSummaryRow[]; total: number } {
  const rows = REVIEW_ROWS.map((row) => {
    let count = 0;
    if (review) {
      if (row.key === "include-in-report") count = review.report_candidates ?? 0;
      else if (row.key === "bookmark") count = review.case_json?.bookmarks ?? 0;
      else count = review.by_status?.[row.key] ?? 0;
    }
    return { ...row, count };
  });
  const total = review ? Object.values(review.by_status ?? {}).reduce((sum, value) => sum + value, 0) : 0;
  return { rows, total };
}

// --- keywords ---------------------------------------------------------------

export interface KeywordRow {
  id: string;
  label: string;
  /** Search query (`q=`) the row opens. */
  query: string;
  source: "profile" | "saved";
  savedSearch?: SavedSearch;
}

/** Run-profile keywords first, then saved searches (deduplicated by query). */
export function keywordRows(profileKeywords: readonly string[], saved: readonly SavedSearch[]): KeywordRow[] {
  const rows: KeywordRow[] = [];
  const seen = new Set<string>();
  for (const keyword of profileKeywords) {
    const query = keyword.trim();
    if (!query || seen.has(query)) continue;
    seen.add(query);
    rows.push({ id: `profile:${query}`, label: query, query, source: "profile" });
  }
  saved.forEach((search, index) => {
    const query = (search.keywords ?? []).join(" ").trim();
    if (!query) return;
    rows.push({
      id: `saved:${index}:${search.name}`,
      label: search.name || query,
      query,
      source: "saved",
      savedSearch: search,
    });
  });
  return rows;
}

// --- exports ----------------------------------------------------------------

export const EXPORT_TYPE_LABEL: Record<string, string> = {
  "case-report": "보고서",
  "reviewer-bundle": "리뷰어 번들",
  "submission-manifest": "제출 매니페스트",
  "validation-package": "검증 패키지",
  extract: "선택 추출",
};

export function exportTypeLabel(entry: ExportEntry): string {
  return entry.label || EXPORT_TYPE_LABEL[entry.type] || entry.type;
}

// --- evidence ---------------------------------------------------------------

export function evidenceItemCount(counts: CanonicalCounts | undefined): number | undefined {
  return counts ? (counts.files ?? 0) + (counts.artifacts ?? 0) : undefined;
}
