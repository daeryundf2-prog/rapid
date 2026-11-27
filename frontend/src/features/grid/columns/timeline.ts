import { fetchTimelinePage } from "../../../api/collections";
import type { GridRow } from "../../../contracts/collection";
import { exactEvidenceTime } from "../../../utils/time";
import { timestampKindLabel } from "../../../utils/timeKinds";
import { artifactTypeLabel } from "../../filters/typeLabels";
import type { CollectionDef } from "../types";
import {
  col,
  currentTimezone,
  isRecord,
  makeRef,
  makeRow,
  rowSourceTicks,
  rowTimeZone,
  str,
  strOrNull,
} from "./common";
import { TIME_KINDS_SEPARATOR, timeKindsCell } from "./TimelineCells";

/** Time-kind labels moved to utils/timeKinds.ts (shared with the record view); re-exported. */
export { TIMESTAMP_KIND_LABELS, timestampKindLabel } from "../../../utils/timeKinds";

/** Korean names of the timeline event `source` (core/timeline.py: files, docs, artifacts). */
export const TIMELINE_SOURCE_LABELS: Readonly<Record<string, string>> = {
  files: "파일",
  docs: "문서",
  artifacts: "아티팩트",
};

/** Korean names of the docs source's events (core/timeline.py document events). */
const DOCUMENT_EVENT_LABELS: Readonly<Record<string, string>> = {
  "document-modified": "문서 수정",
  "document-keyword-hit": "문서 키워드 일치",
};

/**
 * 이벤트 column text: the event type's own Korean name (eventlog-event …); a files event
 * (`file-<kind>`) as 파일 · kind; else the Korean name of the artifact row it came from plus the
 * time kind its id carries (`artifact-<type>-<kind>`, core/timeline.py:
 * `artifact-jumplist-automatic-target-accessed` → "자동 Jump List 파일 · 대상 접근"); else the id.
 * The kind stays in the text: 시각 종류 is not a 분석 기본 column, and two events of one record
 * (생성 / 수정) must not read the same.
 */
export function timelineEventLabel(row: GridRow): string {
  const eventType = row.artifactType ?? "";
  const own = eventType ? (artifactTypeLabel(eventType) ?? DOCUMENT_EVENT_LABELS[eventType]) : null;
  if (own) return own;
  if (row.provider === "files" && eventType.startsWith("file-"))
    return `파일 · ${timestampKindLabel(eventType.slice("file-".length))}`;
  const sourceType = str(row.fields.sourceArtifactType);
  const sourceLabel = sourceType ? artifactTypeLabel(sourceType) : null;
  if (!sourceLabel) return eventType;
  const prefix = `artifact-${sourceType}-`;
  const kind = eventType.startsWith(prefix) ? eventType.slice(prefix.length) : "";
  return kind ? `${sourceLabel} · ${timestampKindLabel(kind)}` : sourceLabel;
}

export function timestampKindOf(raw: Record<string, unknown>): string {
  return str(raw.timestamp_kind ?? raw.ts_kind ?? raw.timestamp_label);
}

/**
 * Every time kind of one event (parser-quality r2): label variants of the same record and instant
 * (created/modified, run/run-1, …) are merged into one event whose `labels` lists them, primary
 * (`timestamp_kind`) first. Older outputs: just the primary kind.
 */
export function timestampKindsOf(raw: Record<string, unknown>): string[] {
  const primary = timestampKindOf(raw);
  const labels = Array.isArray(raw.labels) ? raw.labels.map(str).filter(Boolean) : [];
  const ordered = primary ? [primary, ...labels] : labels;
  return [...new Set(ordered)];
}

/** Korean labels of an event's time kinds, joined ("생성 · 수정"; TIME_KINDS_SEPARATOR). */
export function timeKindsText(kinds: readonly string[]): string {
  return kinds.map(timestampKindLabel).filter(Boolean).join(TIME_KINDS_SEPARATOR);
}

/**
 * Event path of a compact event row: `path`, else the locator context it kept
 * (`details.source_path` / `details.path` / `details.artifact_path`), else `input_file` (r1 rows).
 */
export function timelinePathOf(raw: Record<string, unknown>): string | null {
  const details = isRecord(raw.details) ? raw.details : {};
  return (
    strOrNull(raw.path) ??
    strOrNull(details.source_path) ??
    strOrNull(details.path) ??
    strOrNull(details.artifact_path) ??
    strOrNull(raw.input_file)
  );
}

/** Time kinds of a mapped timeline row (`fields.tsLabels`, else the primary `tsKind`). */
export function tsLabelsOf(row: { fields: Record<string, unknown> }): string[] {
  const list = row.fields.tsLabels;
  if (Array.isArray(list) && list.length) return list.map(str).filter(Boolean);
  const kind = str(row.fields.tsKind);
  return kind ? [kind] : [];
}

export const TIMELINE_PRIORITY = [
  "timestamp",
  "title",
  "eventType",
  "tsKind",
  "source",
  "review",
  "path",
] as const;

export const timelineCollection: CollectionDef = {
  id: "timeline",
  label: "타임라인",
  source: "paged",
  fetch: (runId, query, signal) =>
    fetchTimelinePage(runId, query.offset, query.limit, signal, query.rowConditions, query.sort),
  mapRow: (raw, position) => {
    // A condition-filtered page (r4 §2.3) numbers its events by `record_index` (position in `events`).
    const index =
      typeof raw.record_index === "number" && Number.isInteger(raw.record_index) && raw.record_index >= 0
        ? raw.record_index
        : position;
    const kinds = timestampKindsOf(raw);
    const details = isRecord(raw.details) ? raw.details : {};
    return makeRow(
      makeRef("timeline", `/events/${index}`),
      {
        title:
          strOrNull(raw.summary) ??
          strOrNull(details.title) ??
          strOrNull(raw.event_type) ??
          `이벤트 ${index + 1}`,
        sourcePath: timelinePathOf(raw),
        timestamp: strOrNull(raw.timestamp),
        artifactType: strOrNull(raw.event_type),
        provider: strOrNull(raw.source),
      },
      {
        source: str(raw.source),
        eventType: str(raw.event_type),
        inputFile: str(raw.input_file),
        tsKind: kinds[0] ?? "",
        // Every time kind of the event, primary first (labels[]), and their Korean reading.
        tsLabels: kinds,
        timeKinds: timeKindsText(kinds),
        tsZone: str(raw.timezone),
        // Exact UTC instant (decimal 100 ns ticks, a string so no double rounding).
        ...(typeof details.timestamp_utc_ticks === "string" ? { tsTicks: details.timestamp_utc_ticks } : {}),
        // The artifact row the event came from (`details.source_record` {output, row_index}) and
        // its type: the viewer's "원본 아티팩트 열기" pivot.
        ...(isRecord(details.source_record) ? { sourceRecord: details.source_record } : {}),
        ...(strOrNull(details.artifact_type) ? { sourceArtifactType: str(details.artifact_type) } : {}),
      },
    );
  },
  columns: [
    {
      ...col.timestamp(190, ["analysis", "compact", "source"]),
      // The narrowest the KST time reads whole; a narrow pane keeps 요약 beside it (fe-audit A5).
      minWidth: 150,
      // Server sort of the whole (filtered) timeline (`GET /timeline?sort=timestamp`).
      sortKey: "timestamp",
      // 시각 tooltip: the formatted time plus what it means ("수정", "실행 3회차", …) and its zone note.
      tooltip: (r) => {
        const time = r.timestamp
          ? (exactEvidenceTime(r.timestamp, currentTimezone(), {
              sourceZone: rowTimeZone(r),
              rawFiletime: rowSourceTicks(r),
            })?.display ?? r.timestamp)
          : "";
        const kind = timeKindsText(tsLabelsOf(r)) || timestampKindLabel(str(r.fields.tsKind));
        const zone = str(r.fields.tsZone);
        return [
          time,
          kind ? `시각 종류: ${kind}` : "",
          zone === "local-unknown" ? "원본이 지역 시각(UTC 변환 미검증)" : "",
        ]
          .filter(Boolean)
          .join(" · ");
      },
    },
    // 시각 종류: the primary kind plus "+n" when label variants were merged into the event.
    col.field("tsKind", "시각 종류", 120, ["source"], (r) => str(r.fields.tsKind) || null, {
      format: (r) => {
        const kinds = tsLabelsOf(r);
        const primary = timestampKindLabel(str(r.fields.tsKind));
        return kinds.length > 1 ? `${primary} +${kinds.length - 1}` : primary;
      },
      tooltip: (r) => {
        const kinds = tsLabelsOf(r);
        return kinds.length > 1 ? `${timeKindsText(kinds)} (${kinds.join(", ")})` : str(r.fields.tsKind);
      },
      render: timeKindsCell,
    }),
    // 출처 / 이벤트 read in Korean; the raw ids stay the filter value and the tooltip.
    col.field("source", "출처", 90, ["analysis", "compact", "source"], (r) => r.provider, {
      format: (r) => TIMELINE_SOURCE_LABELS[r.provider ?? ""] ?? r.provider ?? "",
      tooltip: (r) => r.provider ?? "",
    }),
    col.field("eventType", "이벤트", 160, ["analysis", "compact"], (r) => r.artifactType, {
      format: timelineEventLabel,
      tooltip: (r) => r.artifactType ?? "",
    }),
    col.title("요약", 380),
    col.review(),
    col.path(420),
  ],
  // A narrow pane keeps what happened next to when (fe-audit A5): 시각 > 요약 > 이벤트 > 시각 종류 > 출처 > 선별 > 경로.
  widthPriority: () => TIMELINE_PRIORITY,
};
