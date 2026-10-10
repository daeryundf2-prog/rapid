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
  run: (ctx: CommandContext) => void | Promise<void>;
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
  priority1to5: "1-5",
  viewerBack: "Alt+ArrowLeft",
  viewerForward: "Alt+ArrowRight",
  help: "?",
  close: "Escape",
} as const;
