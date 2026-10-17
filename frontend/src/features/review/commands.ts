/**
 * Shell commands of the review tools (AXIOM E3): 태그 관리, 메모·이력, 클래식 분할 (`),
 * 미디어 흐리게 (Shift+B). Each either runs or gives a Korean DisabledReason; toggles say
 * their new state once through the polite announcer.
 */

import { announce } from "../../a11y";
import { NO_RUN_REASON } from "../../commands/reasons";
import { type Command, KEY_MAP } from "../../contracts/command";
import { stageHasViewer, stageOf } from "../../router";
import { useAppStore } from "../../state/store";
import { markDisabledReason, targetAsGridRow } from "../viewer/citation";
import { useReviewToolsUi } from "./uiStore";
import { useViewPrefs } from "./viewPrefs";

export const TAG_MANAGER_COMMAND = "review.tags.manage";
export const NOTE_PANEL_COMMAND = "viewer.notePanel";
export const CLASSIC_SPLIT_COMMAND = "view.classicSplit";
export const MEDIA_BLUR_COMMAND = "view.mediaBlur";

export const CLASSIC_STAGE_REASON = "탐색·검토 단계에서만 쓸 수 있습니다";
export const CLASSIC_NARROW_REASON = "창 너비가 1200px 이상일 때 쓸 수 있습니다";
export const NO_NOTE_ROW_REASON = "뷰어에 표시된 행이 없습니다. 그리드에서 행을 선택하세요";

export function classicSplitReason(): string | undefined {
  const s = useAppStore.getState();
  if (!s.route.runId) return NO_RUN_REASON;
  if (!stageHasViewer(stageOf(s.route))) return CLASSIC_STAGE_REASON;
  if (s.viewerIsDrawer) return CLASSIC_NARROW_REASON;
  return undefined;
}

export function toggleClassicSplit(): void {
  const prefs = useViewPrefs.getState();
  const next = !prefs.classicSplit;
  prefs.setClassicSplit(next);
  announce(next ? "클래식 분할 보기를 켰습니다. 격자 위, 세부 정보 아래" : "클래식 분할 보기를 껐습니다");
}

export function toggleMediaBlur(): void {
  const prefs = useViewPrefs.getState();
  const next = !prefs.mediaBlur;
  prefs.setMediaBlur(next);
  announce(next ? "미디어 흐리게를 켰습니다" : "미디어 흐리게를 껐습니다");
}

export function reviewToolCommands(): Command[] {
  return [
    {
      id: TAG_MANAGER_COMMAND,
      label: "태그 관리…",
      group: "review",
      icon: "tag",
      disabledReason: (ctx) => (ctx.runId ? undefined : NO_RUN_REASON),
      run: (ctx) => {
        if (ctx.runId) useReviewToolsUi.getState().openTagManager(ctx.runId);
      },
    },
    {
      id: NOTE_PANEL_COMMAND,
      label: "메모·이력…",
      group: "review",
      icon: "message",
      disabledReason: (ctx) => {
        if (!ctx.runId) return NO_RUN_REASON;
        const target = useAppStore.getState().viewerTarget;
        if (!target) return NO_NOTE_ROW_REASON;
        return markDisabledReason(target, "relevant");
      },
      run: () => {
        const s = useAppStore.getState();
        const target = s.viewerTarget;
        if (!target) return;
        useReviewToolsUi
          .getState()
          .openNotePanel({ runId: target.runId, row: s.viewerRow ?? targetAsGridRow(target) });
      },
    },
    {
      id: CLASSIC_SPLIT_COMMAND,
      label: "클래식 분할 보기 (격자 위·세부 아래)",
      group: "viewer",
      icon: "columns",
      shortcut: KEY_MAP.classicSplit,
      disabledReason: () => classicSplitReason(),
      run: toggleClassicSplit,
    },
    {
      id: MEDIA_BLUR_COMMAND,
      label: "미디어 흐리게",
      group: "viewer",
      icon: "eye",
      shortcut: KEY_MAP.mediaBlur,
      run: toggleMediaBlur,
    },
  ];
}
