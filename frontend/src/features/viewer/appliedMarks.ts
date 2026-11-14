/** The viewer toolbar's optimistic marks for one row (pressed / un-pressed before the row catches up). */
export interface AppliedMarks {
  key: string;
  actions: string[];
  cleared: string[];
}

/**
 * The toolbar's marks after an un-press of `clears` on row `key`: those marks are off, except the
 * status the un-press went back to (`restored`, when it is a judgement), which is on.
 */
export function appliedAfterUnpress(
  prev: AppliedMarks,
  key: string,
  clears: readonly string[],
  restored: string | undefined,
): AppliedMarks {
  const base = prev.key === key ? prev : { actions: [], cleared: [] };
  const back: string[] = restored && restored !== "unreviewed" ? [restored] : [];
  return {
    key,
    actions: [...base.actions.filter((a) => !clears.includes(a)), ...back],
    cleared: [...base.cleared.filter((a) => !clears.includes(a)), ...clears.filter((a) => !back.includes(a))],
  };
}
