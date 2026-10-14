import { fetchTimelinePage } from "../../../api/collections";
import { formatTimestamp } from "../../../utils/time";
import type { CollectionDef } from "../types";
import { col, currentTimezone, isRecord, makeRef, makeRow, str, strOrNull } from "./common";
import { TIME_KINDS_SEPARATOR, timeKindsCell } from "./TimelineCells";

/** Semantic time labels of timeline events (core/timeline.py TIMELINE_FIELD_MAP) → Korean. */
export const TIMESTAMP_KIND_LABELS: Readonly<Record<string, string>> = {
  created: "생성",
  modified: "수정",
  accessed: "접근",
  changed: "변경",
  "mft-modified": "MFT 변경",
  event: "이벤트",
  run: "실행",
  "last-run": "마지막 실행",
  "last-written": "키 마지막 기록",
  "last-visited": "마지막 방문",
  visited: "방문",
  installed: "설치",
  registered: "등록",
  "first-connected": "최초 연결",
  "last-connected": "마지막 연결",
  "download-start": "다운로드 시작",
  "download-end": "다운로드 완료",
  taken: "촬영",
  "archive-entry-modified": "압축 항목 수정",
};

/**
 * Korean label of an event's time kind (`timestamp_kind`, also read as `ts_kind` /
 * `timestamp_label`). Numbered run times ("run-3", Prefetch's 8 slots) read "실행 3".
 */
export function timestampKindLabel(kind: string): string {
  if (!kind) return "";
  const numbered = /^(.*)-(\d+)$/.exec(kind);
  if (numbered?.[1] && TIMESTAMP_KIND_LABELS[numbered[1]] && !TIMESTAMP_KIND_LABELS[kind]) {
    return `${TIMESTAMP_KIND_LABELS[numbered[1]]} ${numbered[2]}`;
  }
  return TIMESTAMP_KIND_LABELS[kind] ?? kind;
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

export const timelineCollection: CollectionDef = {
  id: "timeline",
  label: "타임라인",
  source: "paged",
  fetch: (runId, query, signal) => fetchTimelinePage(runId, query.offset, query.limit, signal),
  mapRow: (raw, index) => {
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
      },
    );
  },
  columns: [
    {
      ...col.timestamp(190, ["analysis", "compact", "source"]),
      // 시각 tooltip: the formatted time plus what it means ("수정", "실행 3", …) and its zone note.
      tooltip: (r) => {
        const time = r.timestamp ? formatTimestamp(r.timestamp, currentTimezone()) : "";
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
    col.field("source", "출처", 90, ["analysis", "compact", "source"], (r) => r.provider),
    col.field("eventType", "이벤트", 160, ["analysis", "compact"], (r) => r.artifactType),
    col.title("요약", 380),
    col.review(),
    col.path(420),
  ],
};
