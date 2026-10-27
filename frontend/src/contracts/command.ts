/**
 * Command — the single registry behind the command palette (Ctrl K), the
 * keyboard map, toolbar buttons and the tree. Every user-visible action is a
 * Command; a button is just a view of a Command. This is what makes
 * "every button does something" checkable: a Command either runs or reports
 * `disabledReason`, never silently returns.
 */

export type CommandGroup = "navigate" | "case" | "search" | "grid" | "viewer" | "review" | "export" | "app";

export interface CommandContext {
  runId: string | null;
  collection: string | null;
  selectedRowKeys: string[];
  focusedRowKey: string | null;
  viewerHasTarget: boolean;
  runIsActive: boolean;
  /** A resume / restart of the current run is in flight or already running (optional). */
  runRetryInFlight?: boolean;
}

export interface Command {
  id: string;
  /** Korean label shown in palette, tooltip and help. */
  label: string;
  group: CommandGroup;
  /** Single canonical shortcut (see plan U5); undefined = none. */
  shortcut?: string;
  /** Icon id from frontend/src/icons. */
  icon?: string;
  /** Returns a Korean reason when the command cannot run now; undefined = enabled. */
  disabledReason?: (ctx: CommandContext) => string | undefined;
  /** Resolving to `false` means the command ran but failed (callers must not show it as applied). */
  run: (ctx: CommandContext) => void | Promise<void> | Promise<boolean>;
}

/** The canonical key map. Keys listed here may not be reused elsewhere. */
export const KEY_MAP = {
  palette: "Ctrl+K",
  gridFilter: "/",
  rowDown: "J",
  rowUp: "K",
  openViewer: "Enter",
  toggleSelect: "Space",
  markRelevant: "R",
  markExcluded: "X",
  markNeedsReview: "I",
  bookmark: "B",
  viewerBack: "Alt+ArrowLeft",
  viewerForward: "Alt+ArrowRight",
  help: "?",
  close: "Escape",
  /** Explorer views (S9 ViewSwitch, plan X12). */
  viewColumns: "Alt+Shift+1",
  viewThumbnails: "Alt+Shift+2",
  viewChat: "Alt+Shift+3",
  viewHistogram: "Alt+Shift+4",
  /** 행(카드) 보기 · 지도 대체 보기 (r4 §2.3; Alt+Shift+5/6 were free). */
  viewCards: "Alt+Shift+5",
  viewMap: "Alt+Shift+6",
  /** Stage rail (console-ia §3): 접수 · 처리 · 탐색 · 검토 · 보고. */
  stageIntake: "Alt+1",
  stageProcess: "Alt+2",
  stageExplore: "Alt+3",
  stageReview: "Alt+4",
  stageReport: "Alt+5",
  /** 조건 패널 (viewer-families U-F1): search conditions, 특이사항, 열 구성, 밀도. */
  conditions: "F",
  /** 탐색 트리: 결과 없는 계열 표시/숨김 (viewer-families U-F7). */
  treeEmpty: "T",
  /** Viewer in its own window (U-F2). */
  viewerPopout: "Ctrl+Shift+V",
  /** Viewer window only: mode tabs 1–9 (원본 · 헥스 · SQLite · 이미지 · 문서 · 메일 · 미디어 · 메타 · 계열). */
  viewerModes: "1-9",
  /** Review tags (AXIOM E3): 1–9 apply the case tag bound to the digit in 태그 관리 (1–5 default: 우선순위 n). */
  tagShortcuts: "1-9",
  /** Classic split (AXIOM E3): grid above, details below. */
  classicSplit: "`",
  /** Media gallery examiner protection (AXIOM E3): blur images. B stays 북마크. */
  mediaBlur: "Shift+B",
  /** 계열 (R7 갈래 A): the focused row's family in the grid + the viewer's 계열 tab. */
  familyView: "Shift+F",
  /** 상위 항목으로 (R7 갈래 A): the focused row's parent item. */
  familyParent: "U",
} as const;
