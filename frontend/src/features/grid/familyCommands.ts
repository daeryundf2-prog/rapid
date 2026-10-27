/**
 * 계열 commands of the grid (R7 갈래 A, Nuix family pivots):
 *
 * - 계열 보기 (Shift+F): the focused row's family listed (`family=`) with the row in the 계열 tab;
 * - 상위 항목으로 (U): its parent item, the parent's family listed, the parent in the 계열 tab;
 * - 선택을 상위+하위 항목으로 확장: every selected row's family (`GET /family-expansion`) listed and
 *   selected, so 일괄 태그 · 표시 · CSV act on whole families in one review request.
 *
 * All three only read (GET); the batch actions that follow keep their own confirmations.
 */

import { fetchFamily, fetchFamilyExpansion, itemRef, parseItemRef, rowRefOfItem } from "../../api/families";
import type { GridRow } from "../../contracts/collection";
import { type Command, KEY_MAP } from "../../contracts/command";
import { rowKeyOf } from "../../state/slices/selection";
import { useAppStore } from "../../state/store";
import { familyRoute } from "../viewer/familyNav";
import type { GridCommandHost } from "./gridCommands";
import { reviewLocatorOf } from "./gridCommands";

export const FAMILY_VIEW_COMMAND = "grid.family.view";
export const FAMILY_PARENT_COMMAND = "grid.family.parent";
export const FAMILY_EXPAND_COMMAND = "grid.family.expandSelection";

export const NO_FAMILY_ROW = "계열은 파일·아티팩트·분석 결과 행에서 볼 수 있습니다.";
export const NO_PARENT = "상위 항목이 없습니다(이 항목이 최상위 항목입니다).";
const NO_ROW = "행을 먼저 선택하세요.";
const NO_RUN = "열린 케이스가 없습니다.";
export const EXPAND_COLLECTION_REASON = "파일·아티팩트 목록에서만 선택을 계열로 확장할 수 있습니다.";
export const EXPAND_MAX = 500;

/** The item ref of a grid row: its own, or the run-output row a search hit names. */
export function rowItemRef(row: GridRow): string | null {
  const review = reviewLocatorOf(row);
  if (review) {
    return itemRef({
      collection: review.collection as GridRow["ref"]["collection"],
      kind: review.kind,
      locator: review.pointer,
    });
  }
  return itemRef(row.ref);
}

function annotatedTopWithoutParent(row: GridRow): boolean {
  const info = row.fields.familyInfo as { parent?: unknown } | undefined;
  return Boolean(info) && !info?.parent;
}

export function buildFamilyCommands(hostRef: { current: GridCommandHost }): Command[] {
  const host = () => hostRef.current;
  const focusedItem = (): { row: GridRow; ref: string } | null => {
    const row = host().getFocusedRow();
    const ref = row ? rowItemRef(row) : null;
    return row && ref ? { row, ref } : null;
  };
  const rowReason = (): string | undefined => {
    if (!host().runId) return NO_RUN;
    const row = host().getFocusedRow();
    if (!row) return NO_ROW;
    return rowItemRef(row) ? undefined : NO_FAMILY_ROW;
  };
  const selectionRows = (): GridRow[] => {
    const selected = host().getSelectedRows();
    if (selected.length) return selected;
    const row = host().getFocusedRow();
    return row ? [row] : [];
  };

  return [
    {
      id: FAMILY_VIEW_COMMAND,
      label: "계열 보기",
      group: "grid",
      icon: "layers",
      shortcut: KEY_MAP.familyView,
      disabledReason: rowReason,
      run: () => {
        const item = focusedItem();
        const runId = host().runId;
        if (!item || !runId) return;
        const route = familyRoute(runId, item.ref, item.ref);
        if (route) useAppStore.getState().navigate(route);
      },
    },
    {
      id: FAMILY_PARENT_COMMAND,
      label: "상위 항목으로",
      group: "grid",
      icon: "chevron-up",
      shortcut: KEY_MAP.familyParent,
      disabledReason: () => {
        const reason = rowReason();
        if (reason) return reason;
        const row = host().getFocusedRow();
        return row && annotatedTopWithoutParent(row) ? NO_PARENT : undefined;
      },
      run: async () => {
        const item = focusedItem();
        const runId = host().runId;
        if (!item || !runId) return;
        try {
          const data = await fetchFamily(runId, item.ref, { direction: "up" });
          const parent = data.parent;
          if (!parent) {
            host().toast(NO_PARENT, "info");
            return;
          }
          if (!parent.navigable) {
            host().toast(
              `상위 항목 '${parent.title || "원본 파일"}'은(는) 행으로 기록되지 않았습니다(계열 탭에서 확인).`,
              "info",
            );
            return;
          }
          const route = familyRoute(runId, parent.ref, data.top.ref);
          if (route) useAppStore.getState().navigate(route);
        } catch (error) {
          host().toast(
            `상위 항목을 찾지 못했습니다: ${error instanceof Error ? error.message : String(error)}`,
            "error",
          );
        }
      },
    },
    {
      id: FAMILY_EXPAND_COMMAND,
      label: "선택을 상위+하위 항목으로 확장",
      group: "grid",
      icon: "layers",
      disabledReason: () => {
        const h = host();
        if (!h.runId) return NO_RUN;
        if (h.collection.id !== "artifacts" && h.collection.id !== "files") return EXPAND_COLLECTION_REASON;
        const rows = selectionRows();
        if (rows.length === 0) return "선택된 행이 없습니다.";
        if (!rows.some((row) => rowItemRef(row))) return NO_FAMILY_ROW;
        if (rows.length > EXPAND_MAX) return `한 번에 ${EXPAND_MAX}개 행까지 확장할 수 있습니다.`;
        return undefined;
      },
      run: async () => {
        const h = host();
        const runId = h.runId;
        if (!runId) return;
        const refs = [
          ...new Set(
            selectionRows()
              .map(rowItemRef)
              .filter((ref): ref is string => ref !== null),
          ),
        ];
        try {
          const expansion = await fetchFamilyExpansion(runId, refs);
          applyExpansion(
            h,
            runId,
            refs,
            expansion.items.map((item) => item.ref),
          );
        } catch (error) {
          h.toast(
            `계열로 확장하지 못했습니다: ${error instanceof Error ? error.message : String(error)}`,
            "error",
          );
        }
      },
    },
  ];
}

/**
 * List the families of `requested` in the grid's own collection and select every expanded row
 * of it; the rows of other lists are counted in the toast (a carved row's files parent, …).
 */
export function applyExpansion(
  host: GridCommandHost,
  runId: string,
  requested: string[],
  expanded: string[],
): void {
  const store = useAppStore.getState();
  const collection = host.collection.id === "files" ? "files" : "artifacts";
  const route = store.route;
  const inventory = collection === "files" && route.category === "inventory";
  const mine: string[] = [];
  let others = 0;
  for (const ref of expanded) {
    const parsed = parseItemRef(ref);
    const row = rowRefOfItem(ref);
    if (!parsed || !row || parsed.collection !== collection) {
      others += 1;
      continue;
    }
    if (collection === "files" && row.locator.startsWith("/inventory/") !== inventory) {
      others += 1;
      continue;
    }
    mine.push(rowKeyOf(row));
  }
  store.navigate({
    runId,
    collection,
    ...(inventory ? { category: "inventory" } : {}),
    family: requested,
  });
  useAppStore.getState().setSelectedRows(mine);
  host.toast(
    `계열로 확장: 이 목록 ${mine.length.toLocaleString("ko-KR")}건 선택` +
      (others ? ` · 다른 목록 ${others.toLocaleString("ko-KR")}건(파일·아티팩트·분석 결과)` : "") +
      " — 일괄 태그·표시는 선택한 행에 한 번에 적용됩니다.",
    "info",
  );
}
