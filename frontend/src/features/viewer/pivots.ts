/**
 * Record pivots (viewer redesign §5): from one record to the rows that share a fact with it —
 * same user/SID, logon ID, hash, target path / executable, registry key, source file — plus the
 * timeline ±5 minutes around its time, a detection's original event and a timeline event's
 * source artifact. Each pivot is a route (a grid field filter `cf=f:<key>:<value>` on the same
 * artifact kind, else a run-wide keyword search), or a reason why it cannot run on this row.
 * The viewer "⋯" menu and the grid row menu list the same pivots.
 */

import type { GridRow } from "../../contracts/collection";
import type { Route } from "../../router";
import { flatValue } from "../../utils/flatValue";
import { shiftIso } from "../../utils/time";
import { layoutFields, recordLayout } from "./fieldSheets";

export type PivotId =
  | "same-user"
  | "same-logon"
  | "same-hash"
  | "same-target"
  | "same-key"
  | "same-source"
  | "timeline-window"
  | "matched-event"
  | "source-artifact";

export const PIVOT_ORDER: readonly PivotId[] = [
  "same-user",
  "same-logon",
  "same-hash",
  "same-target",
  "same-key",
  "same-source",
  "timeline-window",
  "matched-event",
  "source-artifact",
];

export const PIVOT_LABELS: Record<PivotId, string> = {
  "same-user": "같은 사용자/SID",
  "same-logon": "같은 로그온 ID",
  "same-hash": "같은 해시",
  "same-target": "같은 대상 경로/실행 파일",
  "same-key": "같은 레지스트리 키",
  "same-source": "같은 출처 파일",
  "timeline-window": "타임라인 ±5분",
  "matched-event": "탐지 → 원 이벤트 열기",
  "source-artifact": "원본 아티팩트 열기",
};

const REASONS: Record<PivotId, string> = {
  "same-user": "이 레코드에 사용자 SID나 사용자 이름이 없습니다.",
  "same-logon": "이 레코드에 로그온 ID가 없습니다.",
  "same-hash": "이 레코드에 파일 해시(SHA-256/SHA-1)가 없습니다.",
  "same-target": "이 레코드에 대상 경로나 실행 파일이 없습니다.",
  "same-key": "이 레코드에 레지스트리 키 경로가 없습니다.",
  "same-source": "원본 파일 경로가 없는 행입니다.",
  "timeline-window": "이 레코드에 해석할 수 있는 시각이 없습니다.",
  "matched-event": "탐지 행이 아니거나 원 이벤트 위치(matched_event)가 없습니다.",
  "source-artifact": "타임라인 이벤트가 아니거나 원본 레코드 위치(source_record)가 없습니다.",
};

/** ±5 minutes, the window of "타임라인 ±5분". */
export const TIMELINE_WINDOW_MS = 5 * 60_000;

export interface Pivot {
  id: PivotId;
  label: string;
  /** Set when the pivot cannot run on this row. */
  reason?: string;
  route?: Route;
  /** The value pivoted on (menu hint / tests). */
  value?: string;
  /** The record key the value came from. */
  key?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function scalar(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return "";
  return flatValue(value).trim();
}

const USER_KEYS = ["user_sid", "sid", "subject_user_sid", "target_user_sid"];
const USER_NAME_KEYS = ["user_name", "target_user_name", "account_name", "user_name_candidate", "user"];
const LOGON_KEYS = ["logon_id", "target_logon_id", "subject_logon_id"];
const HASH_KEYS = ["sha256", "file_sha256", "sha1", "file_sha1", "file_id"];
const TARGET_KEYS = [
  "target_path",
  "executable_path",
  "application_path",
  "image_path",
  "process_name",
  "new_process_name",
  "referenced_path",
  "executable_hint",
  "command",
];
const KEY_KEYS = ["key", "key_path", "source_key_path"];
const TIME_KEYS = [
  "timestamp",
  "time_created",
  "event_time",
  "last_run_at",
  "key_last_written_at",
  "last_written_at",
  "started_at",
  "modified_at",
  "created_at",
];

const EVENT_DATA_LOGON = ["TargetLogonId", "SubjectLogonId", "LogonId"];
const EVENT_DATA_SID = ["TargetUserSid", "SubjectUserSid", "UserSid"];

function eventDataValue(fields: Record<string, unknown>, names: readonly string[]): string {
  const data = isRecord(fields.event_data) ? fields.event_data : null;
  if (!data) return "";
  const lower = new Map(Object.entries(data).map(([k, v]) => [k.toLowerCase(), v]));
  for (const name of names) {
    const v = scalar(lower.get(name.toLowerCase()));
    if (v && v !== "-" && v !== "0x0" && v !== "S-1-0-0") return v;
  }
  return "";
}

/** First present scalar among `keys`: [key, value]. */
function firstKey(fields: Record<string, unknown>, keys: readonly string[]): [string, string] | null {
  for (const key of keys) {
    const v = scalar(fields[key]);
    if (v && v !== "-") return [key, v];
  }
  return null;
}

/**
 * The route of a value pivot: a field filter on the same artifact kind when the value is a
 * direct `details` key there (exact field, the column added), else a run-wide keyword search.
 */
function valueRoute(row: GridRow, runId: string, key: string, value: string, direct: boolean): Route {
  if (direct && row.ref.collection === "artifacts" && row.ref.kind) {
    return {
      runId,
      collection: "artifacts",
      kind: row.ref.kind,
      cf: [{ col: `f:${key}`, op: ":", value }],
      cols: [`details.${key}`],
    };
  }
  return { runId, collection: "search", q: value.includes(" ") ? `"${value}"` : value };
}

/** Timeline window route around an instant (±`ms`). */
export function timelineWindowRoute(
  runId: string,
  timestamp: unknown,
  ms = TIMELINE_WINDOW_MS,
  tz?: string,
): Route | null {
  const value = typeof timestamp === "string" || typeof timestamp === "number" ? timestamp : null;
  if (value === null) return null;
  const from = shiftIso(value, -ms);
  const to = shiftIso(value, ms);
  if (!from || !to) return null;
  return { runId, collection: "timeline", from, to, ...(tz ? { tz } : {}) };
}

/** `artifacts_<kind>` + row index → the artifact row route (viewer opens it). */
export function artifactRowRoute(runId: string, output: unknown, rowIndex: unknown): Route | null {
  const name = scalar(output)
    .replace(/^rapidtriage-/, "")
    .replace(/\.jsonl?$/, "");
  const kind = /^artifacts[_-](.+)$/.exec(name)?.[1];
  const text = scalar(rowIndex);
  if (!text) return null;
  const index = typeof rowIndex === "number" ? rowIndex : Number(text);
  if (!kind || !Number.isInteger(index) || index < 0) return null;
  const locator = `/artifacts/${index}`;
  return { runId, collection: "artifacts", kind, row: { collection: "artifacts", kind, locator } };
}

/** A detection's original event: `matched_event` {output,row_index} / {record_index} / record id. */
function matchedEventRoute(row: GridRow, runId: string, fields: Record<string, unknown>): Route | null {
  const matched = fields.matched_event;
  if (!isRecord(matched)) return null;
  const source = isRecord(matched.source_record) ? matched.source_record : matched;
  const direct = artifactRowRoute(
    runId,
    source.output ?? `artifacts_${row.ref.kind ?? "eventlog"}`,
    source.row_index ?? source.record_index ?? source.artifact_index,
  );
  if (direct) return direct;
  // Only an EventRecordID: find the event by its record id on the same kind.
  const recordId = scalar(matched.record_id ?? matched.event_record_id);
  if (recordId && row.ref.kind) {
    // The detection's `matched_event` has {path, record_id} (no output row index): filter the
    // events of the same source file on the record id.
    const path = scalar(matched.path);
    return {
      runId,
      collection: "artifacts",
      kind: row.ref.kind,
      types: ["eventlog-event"],
      cf: [{ col: "f:record_id", op: ":", value: recordId }],
      cols: ["details.record_id"],
      ...(path ? { path } : {}),
    };
  }
  return null;
}

export function recordPivots(row: GridRow | null, runId: string, tz?: string): Pivot[] {
  const fields = layoutFields(row);
  const details = row && isRecord(row.fields.details) ? row.fields.details : {};
  const isDetail = (key: string) => Object.hasOwn(details, key);
  const make = (id: PivotId, found: { key: string; value: string; route: Route | null } | null): Pivot =>
    found?.route
      ? { id, label: PIVOT_LABELS[id], route: found.route, value: found.value, key: found.key }
      : { id, label: PIVOT_LABELS[id], reason: row ? REASONS[id] : "뷰어에 표시된 행이 없습니다." };
  if (!row) return PIVOT_ORDER.map((id) => make(id, null));

  const valuePivot = (keys: readonly string[], fallback?: () => [string, string] | null) => {
    const hit = firstKey(fields, keys) ?? fallback?.() ?? null;
    if (!hit) return null;
    const [key, value] = hit;
    // Values read out of EventData ("event_data") are not a column of their own: search them.
    const direct = key !== "event_data" && isDetail(key);
    return { key, value, route: valueRoute(row, runId, key, value, direct) };
  };

  const user = valuePivot(USER_KEYS, () => {
    const sid = eventDataValue(fields, EVENT_DATA_SID);
    if (sid) return ["event_data", sid];
    return firstKey(fields, USER_NAME_KEYS);
  });
  const logon = valuePivot(LOGON_KEYS, () => {
    const id = eventDataValue(fields, EVENT_DATA_LOGON);
    return id ? ["event_data", id] : null;
  });
  // A file hash of the record (not the container file's hash: that is "같은 출처 파일").
  const hash =
    valuePivot(HASH_KEYS) ??
    (row.ref.collection === "files" && row.sha256
      ? { key: "sha256", value: row.sha256, route: valueRoute(row, runId, "sha256", row.sha256, false) }
      : null);
  const target = valuePivot(TARGET_KEYS);
  const regKey = valuePivot(KEY_KEYS);
  const source = row.sourcePath
    ? {
        key: "source_path",
        value: row.sourcePath,
        route: {
          runId,
          collection: row.ref.collection,
          ...(row.ref.kind && row.ref.collection === "artifacts" ? { kind: row.ref.kind } : {}),
          path: row.sourcePath,
        } as Route,
      }
    : null;

  // Timeline: the record's first time field (the core 생성/실행/기록 시각), else the row time.
  const layout = recordLayout(row);
  const timeEntry = layout.core.find((entry) => entry.format === "time");
  const timeKey = timeEntry?.key ?? firstKey(fields, TIME_KEYS)?.[0];
  const timeValue = timeEntry?.raw ?? (timeKey ? fields[timeKey] : row.timestamp);
  const windowRoute = timelineWindowRoute(runId, timeValue ?? row.timestamp, TIMELINE_WINDOW_MS, tz);
  const timeline = windowRoute
    ? { key: timeKey ?? "timestamp", value: scalar(timeValue), route: windowRoute }
    : null;

  const matched = row.artifactType === "eventlog-detection" ? matchedEventRoute(row, runId, fields) : null;
  const sourceRecord = isRecord(row.fields.sourceRecord) ? row.fields.sourceRecord : null;
  const sourceArtifact =
    row.ref.collection === "timeline" && sourceRecord
      ? artifactRowRoute(runId, sourceRecord.output, sourceRecord.row_index)
      : null;

  return [
    make("same-user", user),
    make("same-logon", logon),
    make("same-hash", hash),
    make("same-target", target),
    make("same-key", regKey),
    make("same-source", source),
    make("timeline-window", timeline),
    make("matched-event", matched ? { key: "matched_event", value: "", route: matched } : null),
    make(
      "source-artifact",
      sourceArtifact ? { key: "sourceRecord", value: "", route: sourceArtifact } : null,
    ),
  ];
}
