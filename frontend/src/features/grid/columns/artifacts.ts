import { fetchArtifactsPage } from "../../../api/collections";
import { kindsForCategory } from "../../tree/categories";
import { serverPathFilter } from "../gridUtils";
import type { CollectionDef } from "../types";
import { recordHighlight, summarizeArtifact } from "./artifactSummary";
import {
  col,
  fieldStr,
  isRecord,
  makeRef,
  makeRow,
  recoveryFields,
  sha256Of,
  str,
  strOrNull,
} from "./common";

const TIME_KEYS = [
  "timestamp",
  "time",
  "time_created",
  "last_run_at",
  "last_run_time",
  "last_modified",
  "modified_at",
  "key_last_written_at",
  "event_time",
  "normalized_time",
  "created_at",
];

function firstOf(details: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const text = strOrNull(details[key]);
    if (text) return text;
  }
  return null;
}

const typeColumn = col.field("type", "유형", 160, ["analysis", "compact"], (r) => r.artifactType);
const eventColumns = [
  col.field("eventId", "이벤트ID", 90, ["analysis", "compact"], (r) => fieldStr(r, "eventId")),
  col.field("channel", "채널", 120, ["analysis", "compact"], (r) => fieldStr(r, "channel")),
];
const messageColumn = col.field("detail", "메시지", 420, ["analysis"], (r) => fieldStr(r, "detail"));
const detailColumn = col.field("detail", "내용", 320, ["analysis"], (r) => fieldStr(r, "detail"));
const tail = [
  col.field("provider", "파서", 130, ["analysis", "source"], (r) => r.provider),
  col.field("rules", "탐지 규칙", 160, ["source"], (r) => fieldStr(r, "matchedRules")),
  col.field("supported", "지원", 70, ["source"], (r) => (r.fields.supported === false ? "미지원" : "")),
  col.path(420, ["source"]),
  col.sha256(),
];

export const artifactsCollection: CollectionDef = {
  id: "artifacts",
  label: "아티팩트",
  source: "paged",
  fetch: (runId, query, signal) =>
    fetchArtifactsPage(
      runId,
      query.ref.kind,
      query.offset,
      query.limit,
      signal,
      query.pathContains?.trim() || serverPathFilter(query.text),
      !query.ref.kind && query.ref.category
        ? (available) => kindsForCategory(query.ref.category as string, available)
        : undefined,
    ),
  mapRow: (raw, index, ctx) => {
    const details = isRecord(raw.details) ? raw.details : {};
    const record = isRecord(raw.artifact_record) ? raw.artifact_record : {};
    const recordSource = isRecord(record.source) ? record.source : {};
    const hashes = isRecord(recordSource.hashes) ? recordSource.hashes : {};
    const kind = strOrNull(raw._kind) ?? ctx.ref.kind ?? "";
    const rowIndex = typeof raw._index === "number" ? raw._index : index;
    const path = strOrNull(raw.path) ?? strOrNull(recordSource.source_path);
    const provider = isRecord(raw.provider) ? strOrNull(raw.provider.name) : strOrNull(raw.provider);
    const artifactType = strOrNull(raw.artifact_type) ?? strOrNull(record.artifact_type);
    const summary = summarizeArtifact(artifactType, details, path);
    return makeRow(
      makeRef("artifacts", `/artifacts/${rowIndex}`, kind || undefined),
      {
        title: summary.title || `아티팩트 ${rowIndex + 1}`,
        sourcePath: path,
        timestamp: firstOf(details, TIME_KEYS),
        artifactType,
        provider,
        sha256: sha256Of(
          hashes.sha256,
          details.sha256,
          isRecord(details.source_hashes) ? details.source_hashes.sha256 : null,
        ),
      },
      {
        kind,
        detail: summary.detail,
        eventId: summary.eventId ?? "",
        channel: summary.channel ?? "",
        supported: raw.supported !== false,
        confidence: typeof record.confidence === "number" ? record.confidence : null,
        matchedRules: Array.isArray(raw.matched_rules) ? raw.matched_rules.map(str).join(", ") : "",
        highlight: recordHighlight(details),
        ...recoveryFields(details.recovery),
        details,
      },
    );
  },
  columns: [col.title("항목", 320), col.review(), typeColumn, detailColumn, col.timestamp(170), ...tail],
  columnsFor: (ref) =>
    ref.kind === "eventlog"
      ? [
          col.title("이벤트", 320),
          col.review(),
          ...eventColumns,
          messageColumn,
          col.timestamp(170),
          typeColumn,
          ...tail,
        ]
      : [col.title("항목", 320), col.review(), typeColumn, detailColumn, col.timestamp(170), ...tail],
};
