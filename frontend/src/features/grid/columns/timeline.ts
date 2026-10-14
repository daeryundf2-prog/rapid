import { fetchTimelinePage } from "../../../api/collections";
import { formatTimestamp } from "../../../utils/time";
import type { CollectionDef } from "../types";
import { col, currentTimezone, makeRef, makeRow, str, strOrNull } from "./common";

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

export const timelineCollection: CollectionDef = {
  id: "timeline",
  label: "타임라인",
  source: "paged",
  fetch: (runId, query, signal) => fetchTimelinePage(runId, query.offset, query.limit, signal),
  mapRow: (raw, index) =>
    makeRow(
      makeRef("timeline", `/events/${index}`),
      {
        title: strOrNull(raw.summary) ?? strOrNull(raw.event_type) ?? `이벤트 ${index + 1}`,
        sourcePath: strOrNull(raw.path),
        timestamp: strOrNull(raw.timestamp),
        artifactType: strOrNull(raw.event_type),
        provider: strOrNull(raw.source),
      },
      {
        source: str(raw.source),
        eventType: str(raw.event_type),
        inputFile: str(raw.input_file),
        tsKind: timestampKindOf(raw),
        tsZone: str(raw.timezone),
      },
    ),
  columns: [
    {
      ...col.timestamp(190, ["analysis", "compact", "source"]),
      // 시각 tooltip: the formatted time plus what it means ("수정", "실행 3", …) and its zone note.
      tooltip: (r) => {
        const time = r.timestamp ? formatTimestamp(r.timestamp, currentTimezone()) : "";
        const kind = timestampKindLabel(str(r.fields.tsKind));
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
    col.field("tsKind", "시각 종류", 110, ["source"], (r) => str(r.fields.tsKind) || null, {
      format: (r) => timestampKindLabel(str(r.fields.tsKind)),
      tooltip: (r) => str(r.fields.tsKind),
    }),
    col.field("source", "출처", 90, ["analysis", "compact", "source"], (r) => r.provider),
    col.field("eventType", "이벤트", 160, ["analysis", "compact"], (r) => r.artifactType),
    col.title("요약", 380),
    col.review(),
    col.path(420),
  ],
};
