import type { GridRow } from "../../contracts/collection";
import type { ViewerMode } from "../../contracts/viewer";
import { TargetHistory } from "./history";

/**
 * Viewer state that outlives the viewer component (review B2-3): switching between the
 * three-pane stages (탐색·검토) and the two-column ones (접수·처리·보고) unmounts the viewer,
 * and Alt+←/→ history and the chosen tab must survive that. One viewer exists at a time, so
 * this is a module singleton; tests call resetViewerSession().
 */
export interface ViewerSession {
  history: TargetHistory;
  /** Grid rows of history entries (record fields for the 메타 tab when navigating back). */
  rows: Map<string, GridRow | null>;
  /** The tab the user picked, for the target it was picked on. */
  userMode: { key: string; mode: ViewerMode } | null;
  /** The URL `mode=` was already applied once (first target only). */
  restoredMode: boolean;
}

function fresh(): ViewerSession {
  return { history: new TargetHistory(), rows: new Map(), userMode: null, restoredMode: false };
}

let session = fresh();

export function viewerSession(): ViewerSession {
  return session;
}

export function resetViewerSession(): void {
  session = fresh();
}
