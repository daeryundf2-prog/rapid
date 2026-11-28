/**
 * Facts the 검토 panel and the 보고 page read from the review board's rows (design review F12/F16):
 * who set each verdict (판정자 filter), what is in the report, what is 관련 있음 but left out, which
 * decisions carry no name, and how far the evidence hashes are verified.
 */

import { useQuery } from "@tanstack/react-query";
import type { CaseEvidence } from "../../api/cases";
import { fetchReviewRows } from "../../api/collections";
import type { ColumnFilter, GridRow } from "../../contracts/collection";
import { decidedByText, reviewCollection } from "../grid/columns/review";
import { UNNAMED_REVIEWER_LABEL } from "./author";

/**
 * Every row of the review board (case-DB marks + case.json bookmarks), mapped like the board.
 * The key starts with "review-map" + run id, so every applied mark refreshes it.
 */
export function useReviewBoardRows(runId: string | null) {
  return useQuery({
    queryKey: ["review-map", runId, "board-rows"],
    queryFn: async ({ signal }) => {
      const page = await fetchReviewRows(runId as string, signal);
      return page.rows.map((raw, index) => reviewCollection.mapRow(raw, index, { ref: { id: "review" } }));
    },
    enabled: runId !== null,
    retry: false,
    staleTime: 30_000,
  });
}

/** 판정자 column filter (URL `cf=reviewer:<name>`): rows whose verdict that reviewer set ("이름 없음" included). */
export function reviewerFilter(label: string): ColumnFilter[] {
  return [{ col: "reviewer", op: ":", value: label }];
}

/** 보고서 column filter: rows left out of the report (with `status=relevant`: 관련 있음 중 미포함). */
export const NOT_IN_REPORT_FILTER: ColumnFilter[] = [{ col: "report", op: ":", value: "미포함" }];

/** People who set the board's verdicts (P2-1: not whoever last wrote a note) with their row counts,
 * most first; "이름 없음" last. Marks without a verdict are not counted. */
export function reviewerCounts(rows: readonly GridRow[]): Array<{ label: string; count: number }> {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const label = decidedByText(row);
    if (label) counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => {
      if (a.label === UNNAMED_REVIEWER_LABEL) return 1;
      if (b.label === UNNAMED_REVIEWER_LABEL) return -1;
      return b.count - a.count || a.label.localeCompare(b.label, "ko");
    });
}

export interface ReportChecklist {
  /** Rows in the report (include_in_report). */
  included: GridRow[];
  /** 관련 있음 rows not in the report (X4: never added automatically). */
  relevantLeftOut: GridRow[];
  /** Verdicts whose setter names nobody ("" / web-ui / local-user). */
  unnamed: number;
  /** Of them, rows in the report (a report item nobody signed). */
  unnamedIncluded: number;
}

export function reportChecklist(rows: readonly GridRow[]): ReportChecklist {
  const included: GridRow[] = [];
  const relevantLeftOut: GridRow[] = [];
  let unnamed = 0;
  let unnamedIncluded = 0;
  for (const row of rows) {
    const inReport = row.fields.includeInReport === true;
    if (inReport) included.push(row);
    else if (row.reviewStatus === "relevant") relevantLeftOut.push(row);
    if (decidedByText(row) === UNNAMED_REVIEWER_LABEL) {
      unnamed += 1;
      if (inReport) unnamedIncluded += 1;
    }
  }
  return { included, relevantLeftOut, unnamed, unnamedIncluded };
}

export interface HashCheck {
  total: number;
  /** Hash compared with the expected value and equal. */
  matched: number;
  /** Compared and different, or the hashing failed. */
  broken: number;
  /** Everything else: only computed (nothing to compare with), not computed, interrupted, running. */
  unverified: number;
}

/** Evidence hash state of the run's case (`GET /api/cases/{id}` hash_status per evidence). */
export function hashCheck(evidence: readonly Pick<CaseEvidence, "hash_status">[]): HashCheck {
  let matched = 0;
  let broken = 0;
  for (const item of evidence) {
    if (item.hash_status === "matched") matched += 1;
    else if (item.hash_status === "mismatched" || item.hash_status === "failed") broken += 1;
  }
  return { total: evidence.length, matched, broken, unverified: evidence.length - matched - broken };
}
