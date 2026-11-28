/**
 * 함께 볼 것 (design-viewer-keys F19): the three pivots an examiner reaches for first — 타임라인 ±5분,
 * 같은 대상, 같은 원본 파일 — at the top of the detail, each with its row count (pivotCounts.ts:
 * lazy, cancelled when the row changes) and its key (Alt+T · Alt+A · Alt+S, the grid's pivot
 * commands). A timeline event's decoded source record fills 같은 대상 (sourceRecord.ts).
 */

import { useEffect, useMemo, useState } from "react";
import { KeyCap } from "../../commands/CommandButton";
import type { GridRow } from "../../contracts/collection";
import { useAppStore } from "../../state/store";
import {
  cachedPivotCount,
  countPivot,
  type PivotCount,
  pivotCountKey,
  pivotCountText,
  rememberPivotCount,
} from "./pivotCounts";
import { PIVOT_LABELS, PIVOT_SHORTCUTS, type Pivot, recordPivots, STRIP_PIVOTS } from "./pivots";
import { useSourceRecord } from "./sourceRecord";

/** Wait this long on a row before counting (J held down never fires requests). */
export const PIVOT_COUNT_DELAY_MS = 300;

type CountState = PivotCount | null | "loading" | "error";

function usePivotCounts(pivots: Pivot[], row: GridRow | null, runId: string): Record<string, CountState> {
  const keys = pivots.map((pivot) => (pivot.route ? pivotCountKey(runId, pivot) : ""));
  const signature = keys.join("|");
  const [counts, setCounts] = useState<Record<string, CountState>>({});
  // biome-ignore lint/correctness/useExhaustiveDependencies: `signature` identifies the pivots
  useEffect(() => {
    if (!row || !runId) return;
    const controller = new AbortController();
    const initial: Record<string, CountState> = {};
    for (const [index, pivot] of pivots.entries()) {
      const key = keys[index] ?? "";
      if (!key) continue;
      const cached = cachedPivotCount(key);
      initial[pivot.id] = cached === undefined ? "loading" : cached;
    }
    setCounts(initial);
    const timer = window.setTimeout(() => {
      for (const [index, pivot] of pivots.entries()) {
        const key = keys[index] ?? "";
        if (!key || cachedPivotCount(key) !== undefined) continue;
        countPivot(pivot, row, runId, controller.signal).then(
          (count) => {
            rememberPivotCount(key, count);
            if (!controller.signal.aborted) setCounts((prev) => ({ ...prev, [pivot.id]: count }));
          },
          () => {
            if (!controller.signal.aborted) setCounts((prev) => ({ ...prev, [pivot.id]: "error" }));
          },
        );
      }
    }, PIVOT_COUNT_DELAY_MS);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [signature, row, runId]);
  return counts;
}

export function PivotStrip({ row, runId }: { row: GridRow | null; runId: string }) {
  const tz = useAppStore((s) => s.route.tz);
  const navigate = useAppStore((s) => s.navigate);
  const source = useSourceRecord(row, runId);
  const pivots = useMemo(() => {
    const all = recordPivots(row, runId, tz, source?.row ?? null);
    return STRIP_PIVOTS.map((id) => all.find((pivot) => pivot.id === id)).filter(
      (pivot): pivot is Pivot => pivot !== undefined,
    );
  }, [row, runId, tz, source?.row]);
  const counts = usePivotCounts(pivots, row, runId);
  if (!row) return null;
  return (
    <nav className="viewer-pivots" aria-label="함께 볼 것" data-testid="viewer-pivots">
      {pivots.map((pivot) => {
        const state = counts[pivot.id];
        const count = !pivot.route
          ? "해당 없음"
          : state === "loading"
            ? "세는 중…"
            : state === "error"
              ? "건수 모름"
              : state
                ? pivotCountText(state)
                : null;
        return (
          <button
            key={pivot.id}
            type="button"
            className="viewer-pivot"
            data-pivot={pivot.id}
            aria-disabled={pivot.route ? undefined : true}
            aria-keyshortcuts={PIVOT_SHORTCUTS[pivot.id]}
            title={pivot.reason ?? pivot.value}
            onClick={() => {
              if (pivot.route) navigate(pivot.route);
            }}
          >
            <span>{PIVOT_LABELS[pivot.id]}</span>
            {count ? <span className="viewer-pivot-count">{count}</span> : null}
            <KeyCap shortcut={PIVOT_SHORTCUTS[pivot.id]} />
          </button>
        );
      })}
    </nav>
  );
}
