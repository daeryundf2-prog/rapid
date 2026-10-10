/**
 * ViewerTarget — what the always-open viewer shows for the selected row.
 *
 * The viewer never reads the grid directly: the grid publishes a ViewerTarget
 * (store `viewer.target`) and the viewer resolves which modes are available
 * from the API (`source-metadata` / `source-preview`), then auto-selects the
 * best mode. Modes the row cannot support are rendered disabled WITH a reason.
 */

import type { RowRef } from "./rowRef";

export type ViewerMode = "source" | "hex" | "sqlite" | "image" | "document" | "email" | "media" | "meta";

export interface ViewerTarget {
  ref: RowRef;
  runId: string;
  /** Evidence path (null for rows without a source file, e.g. derived indicators). */
  sourcePath: string | null;
  /** Hint from the row: lets the viewer pick a mode before metadata arrives. */
  preferredMode?: ViewerMode;
  /** Byte offset / record locator to highlight (hex view, sqlite row). */
  highlight?: { offset?: number; length?: number; table?: string; rowid?: number };
}

export interface ViewerModeState {
  mode: ViewerMode;
  available: boolean;
  /** Korean reason shown in the tooltip when `available === false`. */
  reason?: string;
}

/** The five actions that are always present in the viewer toolbar. */
export type ViewerAction = "open-original" | "hash" | "copy-path" | "cite" | "mark";

/** Review marks the viewer (and the grid batch bar) can apply. */
export type MarkAction = "relevant" | "needs-review" | "excluded" | "include-in-report" | "bookmark";
