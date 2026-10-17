/**
 * 조건 패널 (viewer-families U-F1): the grid's settings — search conditions, 특이사항, 열 구성 and
 * 밀도 — live in one popover behind the "조건" button of the one-line 조건 줄. Its open state is
 * shared so the `grid.conditions` command (key F, palette) and the chips can open it.
 */

import { create } from "zustand";
import { type Command, KEY_MAP } from "../../contracts/command";

interface ConditionPanelState {
  open: boolean;
  /** A 조건 줄 is mounted (the command's disabled reason otherwise). */
  mounted: number;
  setOpen: (open: boolean) => void;
}

export const useConditionPanel = create<ConditionPanelState>((set) => ({
  open: false,
  mounted: 0,
  setOpen: (open) => set({ open }),
}));

export const CONDITIONS_COMMAND_ID = "grid.conditions";
export const NO_CONDITIONS_REASON = "조건을 설정할 목록이 없습니다. 탐색·검토 목록에서 사용하세요";

export function conditionsCommand(): Command {
  return {
    id: CONDITIONS_COMMAND_ID,
    label: "조건 패널 열기 (검색 조건·특이사항·열 구성·밀도)",
    group: "grid",
    shortcut: KEY_MAP.conditions,
    icon: "filter",
    disabledReason: () => (useConditionPanel.getState().mounted > 0 ? undefined : NO_CONDITIONS_REASON),
    run: () => {
      const s = useConditionPanel.getState();
      s.setOpen(!s.open);
    },
  };
}
