/**
 * Review state overlay: the run's case-DB marks (GET /review-map, react-query
 * key ["review-map", runId]) laid over grid rows by run-output locator, so the
 * status chips show the stored state after a reload. Marks invalidate the map
 * and the review counts (useReviewInvalidation). A fetch that finds marks another
 * window changed shows one merged "다른 창에서 변경됨" toast (r8 T-131).
 */

import { type QueryClient, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { announce } from "../../a11y/announcer";
import { getReviewMap, type ReviewMapMark } from "../../api/caseDb";
import type { ReviewMarkBody } from "../../api/collections";
import { pushToast } from "../../components/toastStore";
import type { GridRow } from "../../contracts/collection";
import { toReviewStatus } from "./columns/common";
import { onReviewApplied, onReviewWrite, type ReviewWrite, reviewLocatorTarget } from "./reviewActions";

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

// ---- changes made in another window (r8 T-131) ------------------------------

/** The one toast for marks another window (or another examiner) changed; repeats replace it. */
export const REMOTE_CHANGE_NOTICE = "다른 창에서 변경됨";
/** A write of this tab is matched against fetched maps for this long, then forgotten. */
export const OWN_WRITE_TTL_MS = 120_000;
/** After a write whose rows this tab cannot key (tag tools, 검토 목록 rows), fetches stay quiet this long. */
export const QUIET_AFTER_UNKEYED_WRITE_MS = 10_000;

export function remoteChangeDetail(count: number): string {
  return `표시 ${count.toLocaleString("ko-KR")}건이 다른 창(또는 다른 검토자)에서 바뀌어 목록에 반영했습니다.`;
}

interface OwnWrite {
  mark: ReviewMarkBody;
  at: number;
}

/**
 * Per run: the last fetched map (the baseline), this tab's pending writes, the quiet deadline,
 * the marks of this tab's unkeyed writes in the quiet window (`null`: a tag tool, tags only) and
 * the rows already attributed to them in that window.
 */
interface RemoteTracking {
  baseline: ReviewMap | null;
  own: Map<string, OwnWrite>;
  quietUntil: number;
  unkeyed: Array<ReviewMarkBody | null>;
  quietSeen: Set<string>;
}

const tracking = new Map<string, RemoteTracking>();

function trackingOf(runId: string): RemoteTracking {
  let entry = tracking.get(runId);
  if (!entry) {
    entry = { baseline: null, own: new Map(), quietUntil: 0, unkeyed: [], quietSeen: new Set() };
    tracking.set(runId, entry);
  }
  return entry;
}

/** Forget every baseline and pending write (tests; a new session). */
export function resetRemoteChangeTracking(): void {
  tracking.clear();
}

/** Remember a write of this tab so the next fetched map does not report it as another window's. */
export function recordOwnReviewWrite(write: ReviewWrite, now = Date.now()): void {
  const entry = trackingOf(write.runId);
  const keys = write.rows?.map(rowReviewKey) ?? [null];
  if (!write.mark || keys.some((key) => key === null)) {
    if (now >= entry.quietUntil) entry.unkeyed = [];
    entry.quietUntil = now + QUIET_AFTER_UNKEYED_WRITE_MS;
    entry.unkeyed.push(write.mark);
    entry.quietSeen.clear();
  }
  if (!write.mark) return;
  for (const key of keys) if (key) entry.own.set(key, { mark: write.mark, at: now });
}

/** Does the stored mark show what this tab wrote (status, report flag, note, added tags)? */
function showsOwnWrite(stored: ReviewMapMark, mark: ReviewMarkBody): boolean {
  if (mark.status !== undefined && stored.status !== mark.status) return false;
  if (mark.include_in_report !== undefined && stored.include_in_report !== mark.include_in_report)
    return false;
  if (mark.note !== undefined && stored.note !== mark.note) return false;
  return (mark.add_tags ?? []).every((tag) => stored.tags.includes(tag));
}

function changed(before: ReviewMapMark | undefined, after: ReviewMapMark): boolean {
  if (!before) return true;
  return (
    before.updated_at !== after.updated_at ||
    before.status !== after.status ||
    before.include_in_report !== after.include_in_report ||
    before.note !== after.note ||
    before.tags.join("\u0000") !== after.tags.join("\u0000")
  );
}

/** A tag tool (no mark) changes tags only: status, report flag and note stay as they were. */
function tagsOnly(before: ReviewMapMark | undefined, after: ReviewMapMark): boolean {
  if (!before) return after.status === "unreviewed" && !after.include_in_report && !after.note;
  return (
    before.status === after.status &&
    before.include_in_report === after.include_in_report &&
    before.note === after.note
  );
}

/**
 * Inside the quiet window: can this tab's unkeyed write explain the change? Only once per row
 * (a row that changes again in the window was changed elsewhere), and only by what the write can
 * do — a tag tool changes tags, a status write shows its status. Anything else is reported.
 */
function explainedByUnkeyedWrite(
  entry: RemoteTracking,
  key: string,
  before: ReviewMapMark | undefined,
  after: ReviewMapMark,
): boolean {
  if (entry.quietSeen.has(key)) return false;
  const explained = entry.unkeyed.some((mark) =>
    mark === null ? tagsOnly(before, after) : showsOwnWrite(after, mark),
  );
  if (explained) entry.quietSeen.add(key);
  return explained;
}

/**
 * Compare a freshly fetched map with the run's previous one: the marks that changed and were not
 * written by this tab (or no longer show what this tab wrote) were changed elsewhere. The first
 * fetch of a run only sets the baseline. Returns how many rows another window changed.
 *
 * An empty map after a non-empty one is treated as a failed read (the review map never drops
 * marks: clearing a mark stores `unreviewed`), so it neither reports nor becomes the baseline.
 * Inside the quiet window after an unkeyed write, a change is skipped only when that write can
 * explain it; the rest is still reported (review P2-7: the window used to swallow every change).
 */
export function detectRemoteChanges(runId: string, map: ReviewMap, now = Date.now()): number {
  const entry = trackingOf(runId);
  const previous = entry.baseline;
  if (previous !== null && previous.size > 0 && map.size === 0) return 0;
  entry.baseline = map;
  for (const [key, write] of entry.own) if (now - write.at > OWN_WRITE_TTL_MS) entry.own.delete(key);
  const quiet = now < entry.quietUntil;
  if (!quiet) {
    entry.unkeyed = [];
    entry.quietSeen.clear();
  }
  if (previous === null) return 0;
  let remote = 0;
  for (const [key, mark] of map) {
    const before = previous.get(key);
    if (!changed(before, mark)) continue;
    const own = entry.own.get(key);
    if (own) {
      entry.own.delete(key);
      if (showsOwnWrite(mark, own.mark)) continue;
    }
    if (quiet && explainedByUnkeyedWrite(entry, key, before, mark)) continue;
    remote += 1;
  }
  return remote;
}

/** One merged toast per fetch that found changes from another window (T-131). */
export function notifyRemoteChanges(count: number): void {
  if (count <= 0) return;
  announce(`${REMOTE_CHANGE_NOTICE}. ${remoteChangeDetail(count)}`);
  pushToast(REMOTE_CHANGE_NOTICE, "info", { detail: remoteChangeDetail(count) });
}

onReviewWrite((write) => recordOwnReviewWrite(write));

/** The run's review map (cached; invalidated after every applied mark). */
export function useReviewMap(runId: string | null, enabled = true): ReviewMap | undefined {
  const query = useQuery({
    queryKey: reviewMapKey(runId),
    queryFn: async ({ signal }) => {
      const payload = await getReviewMap(runId as string, signal);
      // A 200 with `error` is an unread case DB, not "no marks": keep the last good map (the query
      // keeps its data on error) and never compare it (review P2-6: a false toast for every mark).
      if (payload.error) throw new Error(payload.error);
      const map = buildReviewMap(payload.marks ?? []);
      notifyRemoteChanges(detectRemoteChanges(runId as string, map));
      return map;
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
