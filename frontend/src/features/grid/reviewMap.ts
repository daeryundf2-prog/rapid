/**
 * Review state overlay: the run's case-DB marks (GET /review-map, react-query
 * key ["review-map", runId]) laid over grid rows by run-output locator, so the
 * status chips show the stored state after a reload. Marks invalidate the map
 * and the review counts (useReviewInvalidation).
 */

import { type QueryClient, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { getReviewMap, type ReviewMapMark } from "../../api/caseDb";
import type { GridRow } from "../../contracts/collection";
import { markWriteSeq, rememberReviewMarks, reviewKey } from "../review/markVersions";
import { toReviewStatus } from "./columns/common";
import { onReviewApplied, reviewLocatorTarget } from "./reviewActions";

export type ReviewMap = ReadonlyMap<string, ReviewMapMark>;

export const reviewMapKey = (runId: string | null) => ["review-map", runId] as const;

/** Maps that list every mark of the run (not truncated): a row without one there has no mark. */
const completeMaps = new WeakSet<ReviewMap>();

export function buildReviewMap(marks: readonly ReviewMapMark[], complete = false): ReviewMap {
  const map = new Map<string, ReviewMapMark>();
  for (const mark of marks) {
    if (mark.collection && mark.locator) map.set(reviewKey(mark.collection, mark.kind, mark.locator), mark);
  }
  if (complete) completeMaps.add(map);
  return map;
}

/** The review-map key of a grid row (null for rows without a run-output locator). */
export function rowReviewKey(row: GridRow): string | null {
  if (row.ref.collection === "review") return null;
  const target = reviewLocatorTarget(row);
  return target ? reviewKey(target.collection, target.kind, target.locator) : null;
}

/**
 * Row with the stored status/tags/note and the mark's version (`fields.markVersion`, what a write
 * from this row expects; F14). A row without a mark in a complete map gets version 0 ("no mark");
 * otherwise rows without a mark are returned as-is.
 */
export function overlayReview(row: GridRow, map: ReviewMap | undefined): GridRow {
  if (!map) return row;
  const key = rowReviewKey(row);
  const mark = key ? map.get(key) : undefined;
  if (!mark) {
    return key && completeMaps.has(map) && row.fields.markVersion !== 0
      ? { ...row, fields: { ...row.fields, markVersion: 0 } }
      : row;
  }
  return {
    ...row,
    // An explicit `unreviewed` mark (a cleared toggle) clears the row's status too.
    reviewStatus:
      mark.status === "unreviewed"
        ? toReviewStatus(null, mark.include_in_report)
        : (toReviewStatus(mark.status, mark.include_in_report) ?? row.reviewStatus),
    tags: mark.tags.length > 0 ? mark.tags : row.tags,
    fields: {
      ...row.fields,
      ...(mark.note ? { note: mark.note } : {}),
      includeInReport: mark.include_in_report,
      ...(typeof mark.version === "number" ? { markVersion: mark.version } : {}),
    },
  };
}

/** The run's review map (cached; invalidated after every applied mark). Each load also records the
 * marks' versions, which the next write sends back (F14). */
export function useReviewMap(runId: string | null, enabled = true): ReviewMap | undefined {
  const query = useQuery({
    queryKey: reviewMapKey(runId),
    queryFn: async ({ signal }) => {
      const since = markWriteSeq();
      const payload = await getReviewMap(runId as string, signal);
      const marks = payload.marks ?? [];
      const complete = payload.truncated !== true;
      rememberReviewMarks(runId as string, marks, !complete, since);
      return buildReviewMap(marks, complete);
    },
    enabled: enabled && runId !== null,
    staleTime: 30_000,
    retry: false,
  });
  return query.data;
}

export function invalidateReviewQueries(queryClient: QueryClient, runId: string): Promise<void> {
  return queryClient.invalidateQueries({
    predicate: (query) => {
      const [head, run, collection] = query.queryKey as unknown[];
      if (run !== runId) return false;
      return (
        head === "review-counts" ||
        head === "review-map" ||
        (head === "collection" && collection === "review")
      );
    },
  });
}

/** Mounted once by the app: every applied mark refreshes review counts, the map and the review board. */
export function useReviewInvalidation(): void {
  const queryClient = useQueryClient();
  useEffect(
    () =>
      onReviewApplied((runId) => {
        void invalidateReviewQueries(queryClient, runId);
      }),
    [queryClient],
  );
}
