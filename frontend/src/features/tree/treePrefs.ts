/**
 * Tree display preference (viewer-families U-F7): empty families — nodes with 0 rows, analyses
 * that never ran, kinds the run does not have — are hidden by default; "빈 계열 표시" (key T)
 * reveals them dimmed with their reason. Persisted per browser profile.
 */

import { create } from "zustand";
import { announce } from "../../a11y";
import { type Command, KEY_MAP } from "../../contracts/command";
import { readStored, writeStored } from "../../state/storage";

export const SHOW_EMPTY_KEY = "rapidtriage.v2.tree.showEmpty";
export const TREE_EMPTY_COMMAND_ID = "tree.toggle-empty";
export const NO_TREE_REASON = "탐색 트리가 열려 있지 않습니다";

interface TreePrefsState {
  showEmpty: boolean;
  /** Mounted trees (the command's disabled reason otherwise). */
  mounted: number;
  setShowEmpty: (show: boolean) => void;
}

export const useTreePrefs = create<TreePrefsState>((set) => ({
  showEmpty: readStored(SHOW_EMPTY_KEY) === "1",
  mounted: 0,
  setShowEmpty: (show) => {
    writeStored(SHOW_EMPTY_KEY, show ? "1" : null);
    set({ showEmpty: show });
  },
}));

/** Tests: re-read the stored preference. */
export function resetTreePrefs(): void {
  useTreePrefs.setState({ showEmpty: readStored(SHOW_EMPTY_KEY) === "1", mounted: 0 });
}

export function treeEmptyCommand(): Command {
  return {
    id: TREE_EMPTY_COMMAND_ID,
    label: "탐색 트리: 결과 없는 계열 표시/숨김",
    group: "navigate",
    shortcut: KEY_MAP.treeEmpty,
    icon: "list",
    disabledReason: () => (useTreePrefs.getState().mounted > 0 ? undefined : NO_TREE_REASON),
    run: () => {
      const s = useTreePrefs.getState();
      s.setShowEmpty(!s.showEmpty);
      announce(s.showEmpty ? "결과 없는 계열을 숨겼습니다." : "결과 없는 계열을 흐리게 표시합니다.");
    },
  };
}
