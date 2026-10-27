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
import { toReviewStatus } from "./columns/common";
import { onReviewApplied, reviewLocatorTarget } from "./reviewActions";

export type ReviewMap = ReadonlyMap<string, ReviewMapMark>;

export const reviewMapKey = (runId: string | null) => ["review-map", runId] as const;

export function reviewKey(collection: string, kind: string, locator: string): string {
  return `${collection}|${collection === "artifacts" || collection === "analysis" ? kind : ""}|${locator}`;
}

export function buildReviewMap(marks: readonly ReviewMapMark[]): ReviewMap {
  const map = new Map<string, ReviewMapMark>();
  for (const mark of marks) {
    if (mark.collection && mark.locator) map.set(reviewKey(mark.collection, mark.kind, mark.locator), mark);
  }
  return map;
}

/** The review-map key of a grid row (null for rows without a run-output locator). */
export function rowReviewKey(row: GridRow): string | null {
  if (row.ref.collection === "review") return null;
  const target = reviewLocatorTarget(row);
  return target ? reviewKey(target.collection, target.kind, target.locator) : null;
}

/**
 * A grouped timeline row (`group=1`, fields.groupMembers = the members' record indexes) stands for
 * its members: a mark stored on any member shows on the row, so it survives the leader changing
 * with the filters (UX-round review). The row's own mark wins; else the first member mark that is
 * not a cleared toggle, else the first one.
 */
function groupMemberMark(row: GridRow, map: ReviewMap): ReviewMapMark | undefined {
  const members = row.fields.groupMembers;
  if (row.ref.collection !== "timeline" || !Array.isArray(members)) return undefined;
  let cleared: ReviewMapMark | undefined;
  for (const member of members) {
    if (typeof member !== "number") continue;
    const mark = map.get(reviewKey("timeline", "", `/events/${member}`));
    if (!mark) continue;
    if (mark.status !== "unreviewed") return mark;
    cleared ??= mark;
  }
  return cleared;
}

/** Row with the stored status/tags/note; rows without a mark are returned as-is. */
export function overlayReview(row: GridRow, map: ReviewMap | undefined): GridRow {
  if (!map || map.size === 0) return row;
  const key = rowReviewKey(row);
  const mark = (key ? map.get(key) : undefined) ?? groupMemberMark(row, map);
  if (!mark) return row;
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
    },
  };
}

/** The run's review map (cached; invalidated after every applied mark). */
export function useReviewMap(runId: string | null, enabled = true): ReviewMap | undefined {
  const query = useQuery({
    queryKey: reviewMapKey(runId),
    queryFn: async ({ signal }) => buildReviewMap((await getReviewMap(runId as string, signal)).marks ?? []),
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
