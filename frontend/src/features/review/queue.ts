/**
 * Review queue (plan todo 17): the next / previous item without a review tag in the current view.
 * Pure on purpose: the grid supplies the items in display order and the command runs the result.
 */

export interface QueueItem {
  key: string;
  /** True when the row carries a user review tag (system tags such as 북마크 do not count). */
  reviewed: boolean;
}

export interface QueueStep {
  key: string;
  /** 1-based position among the unreviewed items (미검토 k). */
  ordinal: number;
  /** Number of unreviewed items (미검토 k/n). */
  total: number;
}

export const QUEUE_NONE_TEXT = "미검토 없음";

/**
 * The next (`dir` 1) or previous (`dir` -1) unreviewed item after `fromKey`, wrapping at the ends.
 * `fromKey` null or not in the list starts from the top (next) or the bottom (previous).
 * Returns null when no unreviewed item is left.
 */
export function stepUnreviewed(
  items: readonly QueueItem[],
  fromKey: string | null,
  dir: 1 | -1,
): QueueStep | null {
  const unreviewed = items.filter((item) => !item.reviewed);
  const total = unreviewed.length;
  if (total === 0) return null;
  const n = items.length;
  const from = fromKey === null ? -1 : items.findIndex((item) => item.key === fromKey);
  const start = from >= 0 ? from : dir === 1 ? -1 : n;
  for (let step = 1; step <= n; step++) {
    const item = items[(((start + dir * step) % n) + n) % n] as QueueItem;
    if (!item.reviewed) return { key: item.key, ordinal: unreviewed.indexOf(item) + 1, total };
  }
  return null;
}

/** The live-region sentence for a step: "미검토 k/n", or "미검토 없음" when none is left. */
export function queueAnnouncement(step: QueueStep | null): string {
  return step ? `미검토 ${step.ordinal}/${step.total}` : QUEUE_NONE_TEXT;
}
