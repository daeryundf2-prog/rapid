/**
 * Decoded artifact records (F2): group a GridRow's decoded fields for the
 * "레코드" section and find the byte range the record came from, so hex opens
 * at the record instead of offset 0.
 *
 * Field names follow the artifact JSONL rows (`details` object), e.g.
 * eventlog-event: timestamp, event_id, record_id, provider_name, computer,
 * user_name, event_message, evtx_record_offset, evtx_record_size,
 * evtx_record_sha256, evtx_chunk_index, caution_labels, evtx_*_status;
 * kakaotalk: source_offset; shellbags: cell_offset/hbin_offset; prefetch:
 * last_run_at, run_count, prefetch_parse_status …
 */

import type { GridRow } from "../../contracts/collection";
import { clipValue, flatValue } from "../../utils/flatValue";

export type RecordGroupId = "core" | "source" | "validation" | "other";

export const RECORD_GROUP_LABELS: Record<RecordGroupId, string> = {
  core: "핵심",
  source: "출처",
  validation: "검증",
  other: "기타",
};

/** Display order inside 핵심. */
const CORE_KEYS = [
  "timestamp",
  // Timeline events: every time kind of the event (labels[], primary first).
  "timeKinds",
  "event_time",
  "last_run_at",
  "modified_at",
  "event_id",
  "record_id",
  "channel",
  "provider",
  "provider_name",
  "computer",
  "user",
  "user_name",
  "user_sid",
  "target_user_name",
  "message",
  "event_message",
  "level",
  "process_id",
  "thread_id",
  "executable_hint",
  "run_count",
  "hive_name",
  "source_key_path",
  "value_names",
  "application_name",
  "application_path",
  "entry_name",
  "description",
  "title",
  "name",
  "value",
  "url",
];

const SOURCE_PATTERN =
  /^(source_path|path|source_index|source_record_id|source_size|size|source_offset|source_length|record_offset|record_size|record_length|chunk_offset|cell_offset|hbin_offset|offset|length|evtx_record_offset|evtx_record_size|evtx_chunk_index|entry_hint|relative_path)$|sha256|sha1|md5|hashes?$/;

const VALIDATION_PATTERN =
  /validation|report_grade|reportability|caution|parse_status|confidence|fidelity|recovery_status|allocation_status|binxml_status|sequence_status|boundary_status|forensic_review|accuracy_gates|commercial|blockers|coverage_status|risk_/;

export interface RecordField {
  key: string;
  /** Display text, clipped to MAX_VALUE_CHARS (with "…" when cut). */
  value: string;
  /** Full flat text: search, copy and "전체 보기" use this, never `value`. */
  full: string;
  /** True when `value` is a clip of `full`. */
  truncated: boolean;
  /** The original value, for structured rendering (nested objects, hash bundles, lists). */
  raw?: unknown;
  /** The key is a direct `details` key (artifact rows): it can be promoted to a grid column. */
  fromDetails?: boolean;
}

export type RecordGroups = Record<RecordGroupId, RecordField[]>;

/** Clipped display text of a record value (see RecordField.full for the whole text). */
export function formatValue(value: unknown): string {
  return clipValue(flatValue(value));
}

export function makeRecordField(key: string, raw: unknown, fromDetails = false): RecordField {
  const full = flatValue(raw);
  const value = clipValue(full);
  return { key, value, full, truncated: value !== full, raw, ...(fromDetails ? { fromDetails } : {}) };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The decoded fields of a row: `fields.details` (S3 artifacts mapping) merged over the other fields. */
export function recordFields(row: GridRow | null): Record<string, unknown> {
  if (!row) return {};
  const { details, ...rest } = row.fields;
  const merged: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(rest)) {
    if (key === "artifact_record") continue;
    merged[key] = value;
  }
  if (isRecord(details)) Object.assign(merged, details);
  // Channel lives in event_tags ("channel:application") for EVTX rows.
  if (merged.channel === undefined && Array.isArray(merged.event_tags)) {
    const tag = merged.event_tags.find((item) => typeof item === "string" && item.startsWith("channel:"));
    if (typeof tag === "string") merged.channel = tag.slice("channel:".length);
  }
  return merged;
}

export function groupRecordFields(row: GridRow | null): RecordGroups {
  const groups: RecordGroups = { core: [], source: [], validation: [], other: [] };
  const fields = recordFields(row);
  const details = row && isRecord(row.fields.details) ? row.fields.details : {};
  const fromDetails = (key: string) => Object.hasOwn(details, key);
  for (const key of CORE_KEYS) {
    const field = makeRecordField(key, fields[key], fromDetails(key));
    if (field.full !== "") groups.core.push(field);
  }
  for (const [key, raw] of Object.entries(fields)) {
    if (CORE_KEYS.includes(key)) continue;
    const field = makeRecordField(key, raw, fromDetails(key));
    if (field.full === "") continue;
    if (SOURCE_PATTERN.test(key)) groups.source.push(field);
    else if (VALIDATION_PATTERN.test(key)) groups.validation.push(field);
    else groups.other.push(field);
  }
  return groups;
}

function num(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) return value;
  if (typeof value === "string" && /^(0x[0-9a-f]+|\d+)$/i.test(value.trim())) {
    const parsed = Number(value.trim());
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
  }
  return null;
}

const EVTX_FILE_HEADER = 0x1000;
const EVTX_CHUNK_SIZE = 0x10000;

/** Byte range of the decoded record inside its source file, when the row carries one. */
export function recordByteRange(row: GridRow | null): { offset: number; length?: number } | null {
  const fields = recordFields(row);
  const pairs: Array<[string, string[]]> = [
    ["evtx_record_offset", ["evtx_record_size"]],
    ["record_offset", ["record_size", "record_length"]],
    ["source_offset", ["source_length", "record_size", "length"]],
    ["chunk_offset", ["chunk_size"]],
    ["offset", ["length", "size"]],
  ];
  for (const [offsetKey, lengthKeys] of pairs) {
    const offset = num(fields[offsetKey]);
    if (offset === null) continue;
    const length = lengthKeys.map((key) => num(fields[key])).find((value) => value !== null && value > 0);
    return length ? { offset, length } : { offset };
  }
  const chunk = num(fields.evtx_chunk_index);
  if (chunk !== null) return { offset: EVTX_FILE_HEADER + chunk * EVTX_CHUNK_SIZE, length: EVTX_CHUNK_SIZE };
  return null;
}

export function hasDecodedRecord(row: GridRow | null): boolean {
  const groups = groupRecordFields(row);
  return groups.core.length + groups.source.length + groups.validation.length + groups.other.length > 0;
}
