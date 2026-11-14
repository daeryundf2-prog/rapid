/**
 * The 탐색 list pane (registerSlots GridSlot): the one DataGrid behind the view switch, beside the
 * 파일 시스템 탐색기 folder tree when that is open. A lazy chunk (T-116, `lazyViews.ts`): the grid,
 * its column sets and the table engine load when a case opens, not on the case list.
 */

import { FsExplorerLayout, fsExplorerOpen } from "../features/explorers/FsExplorer";
import { DataGrid } from "../features/grid/DataGrid";
import { useAppStore } from "../state/store";
import { ViewSwitch } from "./ViewSwitch";

export function ExploreGrid() {
  // A boolean only: a new `row=` (each J/K) must not re-render the pane.
  const explorerOpen = useAppStore((s) => Boolean(s.route.runId) && fsExplorerOpen(s.route));
  const grid = (
    <ViewSwitch>
      <DataGrid />
    </ViewSwitch>
  );
  // 파일 시스템 탐색기 (r4 §2.2): folder tree beside the grid of the selected folder.
  return explorerOpen ? <FsExplorerLayout>{grid}</FsExplorerLayout> : grid;
}
