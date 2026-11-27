/**
 * Local telemetry (docs/telemetry.md): five console-side P0 events, posted to this machine's own
 * RapidTriage server (`POST /api/telemetry/events`), which whitelists, hashes and appends them
 * to the local log. Nothing is sent anywhere else.
 *
 * Privacy: builders take only coded values (enums, counts turned into buckets, artifact kind ids).
 * Paths, file names, search text, row values and reviewer names have no field to go into; the
 * raw tag key rides in `tag` only so the server can store its salted hash.
 */

import { api, authToken } from "../api/client";
import type { Stage } from "../router";

export type TelemetrySurface = "tree" | "timeline" | "search" | "review";
export type TagSurface = "grid" | "viewer" | "search" | "timeline" | "palette" | "shortcut";
export type TagAction = "tag" | "untag" | "bookmark" | "relevant" | "irrelevant" | "other";

export interface TelemetryEvent {
  event:
    | "app_session_started"
    | "grid_loaded"
    | "grid_sorted"
    | "review_stage_entered"
    | "review_tag_applied";
  props: Record<string, string | number | boolean>;
  run_id?: string;
  tag?: string;
}

const COUNT_BUCKETS = ["0", "1-9", "10-99", "100-999", "1k-9k", "10k-99k", "100k-999k", "1m+"] as const;
const IDENT = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;

/** Log-scale bucket of a count ("unknown" when not known); same buckets as the server. */
export function countBucket(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return "unknown";
  if (value === 0) return "0";
  return COUNT_BUCKETS[Math.min(COUNT_BUCKETS.length - 1, 1 + Math.floor(Math.log10(value)))] ?? "unknown";
}

/** A code identifier (artifact kind / collection id) or "other": never free text or a path. */
export function codeId(value: string | null | undefined): string {
  return value && IDENT.test(value) ? value : "other";
}

export function viewportBucket(width: number): string {
  if (width < 640) return "xs";
  if (width < 1024) return "sm";
  if (width < 1440) return "md";
  if (width < 1920) return "lg";
  return "xl";
}

export function localeOf(language: string): string {
  const prefix = language.toLowerCase().split("-")[0];
  return prefix === "ko" || prefix === "en" ? prefix : "other";
}

export function sessionStarted(width: number, language: string): TelemetryEvent {
  return {
    event: "app_session_started",
    props: { viewport_bucket: viewportBucket(width), locale: localeOf(language) },
  };
}

export interface GridLoad {
  runId: string;
  surface: TelemetrySurface;
  artifactType: string;
  total: number | null;
  latencyMs: number;
  serverMs: number | null;
  truncated: boolean;
}

export function gridLoaded(load: GridLoad): TelemetryEvent {
  return {
    event: "grid_loaded",
    run_id: load.runId,
    props: {
      surface: load.surface,
      artifact_type: codeId(load.artifactType),
      row_count_bucket: countBucket(load.total),
      latency_ms: Math.max(0, Math.round(load.latencyMs)),
      ...(load.serverMs !== null ? { server_ms: Math.max(0, Math.round(load.serverMs)) } : {}),
      total_known: load.total !== null,
      truncated: load.truncated,
    },
  };
}

export interface GridSort {
  runId: string;
  surface: TelemetrySurface;
  columnKind: "time" | "text" | "number";
  direction: "asc" | "desc";
  scope: "server" | "loaded";
  loadedRows: number;
  totalRows: number | null;
}

export function gridSorted(sort: GridSort): TelemetryEvent {
  return {
    event: "grid_sorted",
    run_id: sort.runId,
    props: {
      surface: sort.surface,
      column_kind: sort.columnKind,
      direction: sort.direction,
      scope: sort.scope,
      loaded_rows_bucket: countBucket(sort.loadedRows),
      total_rows_bucket: countBucket(sort.totalRows),
    },
  };
}

export function stageEntered(runId: string, stage: Stage): TelemetryEvent {
  return { event: "review_stage_entered", run_id: runId, props: { stage } };
}

export interface TagApplied {
  runId: string;
  action: TagAction;
  rowCount: number;
  surface: TagSurface;
  artifactType: string;
  tag?: string;
}

export function tagApplied(applied: TagApplied): TelemetryEvent {
  return {
    event: "review_tag_applied",
    run_id: applied.runId,
    ...(applied.tag ? { tag: applied.tag } : {}),
    props: {
      action: applied.action,
      row_count: applied.rowCount,
      source_surface: applied.surface,
      artifact_type: codeId(applied.artifactType),
    },
  };
}

/** Grid surface of a collection id: timeline / search / review board, everything else the tree. */
export function surfaceOf(collection: string): TelemetrySurface {
  if (collection === "timeline" || collection === "search" || collection === "review") return collection;
  return "tree";
}

// Off under vitest unless a test turns it on: component tests count their fetch calls.
let enabled = import.meta.env.MODE !== "test";
let warned = false;

export function setTelemetryEnabled(on: boolean): void {
  enabled = on;
}

/** Post one event to the local server; never blocks or throws into the UI. */
export function emit(event: TelemetryEvent): void {
  if (!enabled || !authToken()) return;
  api("/api/telemetry/events", { method: "POST", body: JSON.stringify(event) }).catch((error: unknown) => {
    if (warned) return;
    warned = true;
    console.warn("local telemetry event not recorded", error instanceof Error ? error.message : error);
  });
}
