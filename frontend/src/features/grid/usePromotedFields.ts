import { useCallback, useMemo, useState } from "react";
import { useGridLocalStore } from "./adapter";
import {
  colsToKeys,
  effectiveFieldCols,
  readStoredFieldColumns,
  toggleFieldCol,
  writeStoredFieldColumns,
} from "./columns/fieldColumns";

export interface PromotedFieldsApi {
  /** Promoted details keys of the kind. */
  keys: string[];
  /** Show / hide one details key as a grid column (URL `cols=` + the kind's stored set). */
  toggle: (key: string) => void;
}

/**
 * Promoted record-field columns of one artifact kind, for controls outside the grid
 * (the meta tab's "열로 표시"). While the grid shows that kind the grid route (URL) is
 * updated; otherwise only the kind's stored set changes.
 */
export function usePromotedFields(kind: string | undefined): PromotedFieldsApi {
  const route = useGridLocalStore((s) => s.route);
  const active = !!kind && route.collection.id === "artifacts" && route.collection.kind === kind;
  const [storedTick, setStoredTick] = useState(0);
  // biome-ignore lint/correctness/useExhaustiveDependencies: storedTick re-reads storage after a write
  const cols = useMemo(
    () => (!kind ? [] : active ? effectiveFieldCols(route.cols, kind) : (readStoredFieldColumns(kind) ?? [])),
    [kind, active, route.cols, storedTick],
  );
  const toggle = useCallback(
    (key: string) => {
      if (!kind) return;
      const next = toggleFieldCol(cols, key);
      writeStoredFieldColumns(kind, next);
      if (active) useGridLocalStore.getState().setRoute({ cols: next.length ? next : undefined });
      else setStoredTick((n) => n + 1);
    },
    [kind, active, cols],
  );
  const keys = useMemo(() => colsToKeys(cols), [cols]);
  return useMemo(() => ({ keys, toggle }), [keys, toggle]);
}
