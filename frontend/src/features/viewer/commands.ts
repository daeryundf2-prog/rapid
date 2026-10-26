/**
 * Viewer commands. The toolbar buttons are views of these Commands, and the
 * same objects are registered with the command registry (palette/keymap).
 */

import { type Command, KEY_MAP } from "../../contracts/command";
import type { MarkAction, ViewerTarget } from "../../contracts/viewer";
import { citationDisabledReason } from "../case/caseLink";
import { MARK_LABELS, MARK_ORDER, markDisabledReason } from "./citation";
import { REASONS } from "./modes";

export const NO_TARGET_REASON = "뷰어에 표시된 행이 없습니다.";

export interface ViewerController {
  getTarget(): ViewerTarget | null;
  openOriginal(): Promise<void>;
  copyHash(): Promise<void>;
  copyPath(): Promise<void>;
  copyCitation(): Promise<void>;
  mark(action: MarkAction): Promise<void>;
  back(): void;
  forward(): void;
  canBack(): boolean;
  canForward(): boolean;
}

export const VIEWER_COMMAND_IDS = {
  openOriginal: "viewer.open-original",
  hash: "viewer.hash",
  copyPath: "viewer.copy-path",
  cite: "viewer.cite",
  back: "viewer.back",
  forward: "viewer.forward",
  mark: (action: MarkAction) => `viewer.mark.${action}`,
} as const;

/** Emitted by "같은 출처의 다른 행"; handled by the grid/tree streams. */
export const ROWS_FOR_SOURCE_COMMAND = "navigate.rows-for-source";

export function buildViewerCommands(controller: ViewerController): Command[] {
  const needsTarget = () => (controller.getTarget() ? undefined : NO_TARGET_REASON);
  const needsPath = () => {
    const target = controller.getTarget();
    if (!target) return NO_TARGET_REASON;
    return target.sourcePath ? undefined : REASONS.noPath;
  };
  const commands: Command[] = [
    {
      id: VIEWER_COMMAND_IDS.openOriginal,
      label: "원본 열기",
      group: "viewer",
      icon: "external",
      disabledReason: needsPath,
      run: () => controller.openOriginal(),
    },
    {
      id: VIEWER_COMMAND_IDS.hash,
      label: "해시 복사 (SHA-256)",
      group: "viewer",
      icon: "hash",
      disabledReason: needsPath,
      run: () => controller.copyHash(),
    },
    {
      id: VIEWER_COMMAND_IDS.copyPath,
      label: "경로 복사",
      group: "viewer",
      icon: "copy",
      disabledReason: needsPath,
      run: () => controller.copyPath(),
    },
    {
      id: VIEWER_COMMAND_IDS.cite,
      label: "인용 복사",
      group: "viewer",
      icon: "quote",
      // 사건=…/증거=… prefix: blocked while the main window is still loading the run's case link.
      disabledReason: () => needsTarget() ?? citationDisabledReason(controller.getTarget()?.runId),
      run: () => controller.copyCitation(),
    },
    {
      id: VIEWER_COMMAND_IDS.back,
      label: "뷰어 이전 대상",
      group: "viewer",
      shortcut: KEY_MAP.viewerBack,
      icon: "arrow-left",
      disabledReason: () => (controller.canBack() ? undefined : "이전에 본 대상이 없습니다."),
      run: () => controller.back(),
    },
    {
      id: VIEWER_COMMAND_IDS.forward,
      label: "뷰어 다음 대상",
      group: "viewer",
      shortcut: KEY_MAP.viewerForward,
      icon: "arrow-right",
      disabledReason: () => (controller.canForward() ? undefined : "다음 대상이 없습니다."),
      run: () => controller.forward(),
    },
  ];
  for (const action of MARK_ORDER) {
    commands.push({
      id: VIEWER_COMMAND_IDS.mark(action),
      label: `표시: ${MARK_LABELS[action]}`,
      group: "review",
      icon: action === "bookmark" ? "bookmark" : "flag",
      disabledReason: () => markDisabledReason(controller.getTarget(), action),
      run: () => controller.mark(action),
    });
  }
  return commands;
}

/** Clipboard write with a textarea fallback (non-secure contexts). */
/** Korean reason of a refused copy (r7 L4, C-W10): never the browser's English DOMException text. */
export const CLIPBOARD_DENIED =
  "클립보드에 복사하지 못했습니다 — 브라우저가 접근을 막았습니다(창이 포커스를 잃었거나 권한 없음). 창을 클릭한 뒤 다시 시도하세요.";

export async function writeClipboard(text: string): Promise<void> {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Permission / focus refusal: try the legacy path below, then say why in Korean.
    }
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  let ok = false;
  try {
    ok = typeof document.execCommand === "function" && document.execCommand("copy");
  } catch {
    ok = false;
  }
  area.remove();
  if (!ok) throw new Error(CLIPBOARD_DENIED);
}
