/**
 * Client of the action API v1 (docs/ai-action-api.md) and the selections the console builds
 * for it. The console's 선택 항목 분석 / 관련 항목 표시 send exactly the request an agent would,
 * so the dialog can show that request for delegation.
 */

import { api } from "../../api/client";
import type { GridRow, ReviewStatus } from "../../contracts/collection";
import { reviewLocatorTarget } from "../grid/reviewActions";

export type Relation = "time_window" | "same_path" | "same_name";

export interface RowTarget {
  collection: string;
  kind?: string;
  locator: string;
}

export type ActionSelection =
  | { rows: RowTarget[] }
  | { timeline: { from?: string; to?: string; contains?: string; event_types?: string[] } }
  | {
      related: {
        relation: Relation;
        anchor?: RowTarget;
        at?: string;
        path?: string;
        window_s?: number;
      };
    };

export interface SelectionProfile {
  total: number;
  limit: number;
  over_limit: boolean;
  by_collection: Record<string, number>;
  timeline_rows: number;
  time_range: { first: string; last: string } | null;
  by_source: Record<string, number>;
  by_event_type: Record<string, number>;
  top_paths: { path: string; count: number }[];
  sample: { locator: string; timestamp: string | null; event_type: string | null; summary: string | null }[];
}

export interface MarkRequest {
  selection: ActionSelection;
  mark: { status?: ReviewStatus | "unreviewed"; add_tags?: string[]; include_in_report?: boolean };
  dry_run: boolean;
  actor: { kind: "human" | "agent"; name?: string };
}

export interface MarkResult extends SelectionProfile {
  dry_run: boolean;
  updated_count?: number;
}

const enc = encodeURIComponent;

export function selectRows(runId: string, selection: ActionSelection, sample = 5, signal?: AbortSignal) {
  return api<SelectionProfile>(`/api/runs/${enc(runId)}/actions/select`, {
    method: "POST",
    body: JSON.stringify({ selection, sample }),
    signal,
  });
}

export function markRows(runId: string, request: MarkRequest) {
  return api<MarkResult>(`/api/runs/${enc(runId)}/actions/mark`, {
    method: "POST",
    body: JSON.stringify(request),
  });
}

/** The rows' run-output locators (rows without one, e.g. unsaved search hits, are left out). */
export function rowsSelection(rows: readonly GridRow[]): { rows: RowTarget[] } {
  const targets: RowTarget[] = [];
  for (const row of rows) {
    const target = reviewLocatorTarget(row);
    if (target)
      targets.push(target.kind ? target : { collection: target.collection, locator: target.locator });
  }
  return { rows: targets };
}

/**
 * Rows related to `row`: a timeline row is the server-side anchor; any other row sends its
 * own time / path, which the server matches against the timeline. Null when the row lacks
 * the value the relation needs.
 */
export function relatedSelection(row: GridRow, relation: Relation, windowS: number): ActionSelection | null {
  const isTimeline = row.ref.collection === "timeline" && row.ref.locator.startsWith("/events/");
  if (isTimeline) {
    const anchor = { collection: "timeline", locator: row.ref.locator };
    return { related: { relation, anchor, ...(relation === "time_window" ? { window_s: windowS } : {}) } };
  }
  if (relation === "time_window") {
    return row.timestamp ? { related: { relation, at: row.timestamp, window_s: windowS } } : null;
  }
  return row.sourcePath ? { related: { relation, path: row.sourcePath } } : null;
}

/** Korean reason the row cannot anchor `relation`; undefined when it can. */
export function relationReason(row: GridRow, relation: Relation): string | undefined {
  if (relatedSelection(row, relation, 300)) return undefined;
  return relation === "time_window" ? "이 행에는 시각이 없습니다" : "이 행에는 경로가 없습니다";
}
