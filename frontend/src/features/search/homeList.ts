import type { Command } from "../../contracts/command";
import { useAppStore } from "../../state/store";
import { useGridLocalStore } from "../grid/adapter";

export const OPEN_HOME_LIST_COMMAND = "grid.openHomeList";
const NOT_A_HIT = "색인 검색 결과 행에서만 쓸 수 있습니다";

/**
 * 검색 결과 row menu: open a hit in the list it belongs to (files, documents, an artifact kind,
 * indicators), focused on its own row, where its neighbours and that list's columns are.
 */
export function homeListCommand(): Command {
  const hit = () => {
    const row = useGridLocalStore.getState().focusedRow;
    // A scan match has no address of its own; analysis rows open from their job node.
    return row?.ref.source && row.ref.collection !== "search" && row.ref.collection !== "analysis"
      ? row
      : null;
  };
  return {
    id: OPEN_HOME_LIST_COMMAND,
    label: "원본 목록에서 보기",
    group: "grid",
    icon: "list",
    disabledReason: () => (hit() ? undefined : NOT_A_HIT),
    run: () => {
      const row = hit();
      const { runId } = useAppStore.getState().route;
      if (!row || !runId) return;
      // Without the hit marker the ref is the record's own address, which its list restores.
      const { source: _hit, ...ref } = row.ref;
      useAppStore
        .getState()
        .navigate({ runId, collection: ref.collection, ...(ref.kind ? { kind: ref.kind } : {}), row: ref });
    },
  };
}
