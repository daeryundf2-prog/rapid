import { fetchTimelinePage } from "../../../api/collections";
import { formatEvidenceTime } from "../../../utils/time";
import { timestampKindLabel } from "../../../utils/timeKinds";
import { artifactTypeLabel } from "../../filters/typeLabels";
import { familyForType } from "../../flags/catalog";
import { parseFlags } from "../../flags/flags";
import type { CollectionDef } from "../types";
import { baseName, col, currentTimezone, isRecord, makeRef, makeRow, str, strOrNull } from "./common";
import { familyFactsLine, flagsColumn } from "./families";
import { sourceCountCell, TIME_KINDS_SEPARATOR, timeKindsCell } from "./TimelineCells";

/** Time-kind labels moved to utils/timeKinds.ts (shared with the record view); re-exported. */
export { TIMESTAMP_KIND_LABELS, timestampKindLabel } from "../../../utils/timeKinds";

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

/** Keys naming the thing an event is about (대상 column), in order. */
const TARGET_KEYS = [
  "target_path",
  "executable_path",
  "url",
  "source_url",
  "key_path",
  "path_candidate",
] as const;

function lastSegments(path: string, count: number): string {
  const parts = path.split(/[\\/]+/).filter(Boolean);
  if (parts.length <= count) return parts.join("\\");
  return `…\\${parts.slice(-count).join("\\")}`;
}

/** URL read as host + path (no scheme, query or fragment); the text itself when it is no URL. */
export function urlHostPath(url: string): string {
  try {
    const parsed = new URL(url);
    if (!parsed.host) return url;
    return `${parsed.host}${parsed.pathname === "/" ? "" : parsed.pathname}`;
  } catch {
    return url;
  }
}

/**
 * The thing an event is about (timeline/grid readability C4): a file / executable → its name, a URL →
 * host + path, a registry key → its last two parts; `full` is the whole value (tooltip). Events
 * without one (event logs) read their summary.
 */
export function timelineTarget(raw: Record<string, unknown>): { text: string; full: string } | null {
  const details = isRecord(raw.details) ? raw.details : {};
  for (const key of TARGET_KEYS) {
    const value = strOrNull(details[key]);
    if (!value) continue;
    if (key === "url" || key === "source_url") return { text: urlHostPath(value), full: value };
    if (key === "key_path") return { text: lastSegments(value, 2), full: value };
    return { text: baseName(value) || value, full: value };
  }
  return null;
}

/**
 * 출처 행: the event's source path without the acquisition root (`root` of the timeline), shown as
 * the last two folders + the file name.
 */
export function sourceRowText(path: string | null, root: string | null | undefined): string {
  if (!path) return "";
  let rest = path;
  const base = (root ?? "").replace(/[\\/]+$/, "");
  if (base && rest.toLowerCase().startsWith(base.toLowerCase())) rest = rest.slice(base.length);
  return lastSegments(rest, 3);
}

/** 영역·유형: the Korean name of the source artifact type (catalogue family as fallback). */
export function timelineAreaLabel(type: string | null | undefined): string {
  if (!type) return "";
  if (type.startsWith("eventlog-") && !artifactTypeLabel(type))
    return familyForType("eventlog-event")?.label ?? type;
  return artifactTypeLabel(type) ?? familyForType(type)?.label ?? type;
}

interface TimelineSource {
  artifact_type?: unknown;
  event_type?: unknown;
  path?: unknown;
  record_index?: unknown;
}

/**
 * Older timeline outputs prefix every summary with the producer ("Artifact event: <type> …",
 * "EventLog event: …"; C-D13). The prefix is a raw id the examiner never needs: it is stripped at
 * display (the raw summary stays in the row JSON).
 */
const LEGACY_SUMMARY_PREFIX = /^(?:Artifact event: \S+ |EventLog event: )/;

export function stripLegacySummaryPrefix(summary: string | null): string | null {
  if (!summary) return summary;
  const stripped = summary.replace(LEGACY_SUMMARY_PREFIX, "").trim();
  return stripped || summary;
}

export const timelineCollection: CollectionDef = {
  id: "timeline",
  label: "타임라인",
  source: "paged",
  fetch: (runId, query, signal) =>
    fetchTimelinePage(runId, query.offset, query.limit, signal, query.rowConditions, {
      q: query.text,
      group: query.group === true,
    }),
  widthPriority: () => [
    "timestamp",
    "target",
    "tsKind",
    "area",
    "detail",
    "sourceCount",
    "flags",
    "sourceRow",
    // 선별 only when a loaded event is marked (empty columns go first).
    "review",
  ],
  mapRow: (raw, position, ctx) => {
    // A condition-filtered page (r4 §2.3) numbers its events by `record_index` (position in `events`).
    const index =
      typeof raw.record_index === "number" && Number.isInteger(raw.record_index) && raw.record_index >= 0
        ? raw.record_index
        : position;
    const kinds = timestampKindsOf(raw);
    const details = isRecord(raw.details) ? raw.details : {};
    const sourceType = strOrNull(details.artifact_type);
    const summary = stripLegacySummaryPrefix(strOrNull(raw.summary));
    // An event-log event is about a record of a channel: "Security · 4624" (its summary is 상세).
    const eventId = sourceType?.startsWith("eventlog-") ? strOrNull(details.event_id) : null;
    const target =
      timelineTarget(raw) ??
      (eventId
        ? (() => {
            const text = [strOrNull(details.channel), eventId].filter(Boolean).join(" · ");
            return { text, full: text };
          })()
        : null);
    const path = timelinePathOf(raw);
    const root = strOrNull(ctx.page?.meta?.root);
    // 상세: event logs read their summary (event name / message · account · computer); other
    // events their family's core facts, else the summary when it says more than the target.
    const facts = sourceType?.startsWith("eventlog-")
      ? ""
      : familyFactsLine(sourceType, details, [target?.full ?? ""]);
    const detail = facts || (summary && summary !== target?.full ? summary : "");
    const sources = Array.isArray(raw.sources) ? (raw.sources.filter(isRecord) as TimelineSource[]) : [];
    const sourceCount =
      typeof raw.source_count === "number" && raw.source_count > 0
        ? raw.source_count
        : Math.max(1, sources.length);
    return makeRow(
      makeRef("timeline", `/events/${index}`),
      {
        title: summary ?? strOrNull(details.title) ?? strOrNull(raw.event_type) ?? `이벤트 ${index + 1}`,
        sourcePath: path,
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
        // C4: 대상 (what the event is about, full value in the tooltip), 상세, 영역·유형, 출처 행.
        target: target?.text ?? summary ?? "",
        targetFull: target?.full ?? summary ?? "",
        detail,
        area: timelineAreaLabel(sourceType ?? strOrNull(raw.event_type)),
        sourceRow: sourceRowText(path, root),
        // C1 rule 2: display group (`group=1`) — sources that recorded the same target, second and
        // kind of time; the events themselves stay listed (viewer › 메타).
        sourceCount,
        ...(sources.length
          ? {
              groupSources: sources.map((source) => ({
                artifactType: str(source.artifact_type),
                eventType: str(source.event_type),
                path: str(source.path),
                recordIndex: typeof source.record_index === "number" ? source.record_index : null,
              })),
            }
          : {}),
        ...(Array.isArray(raw.group_members) ? { groupMembers: raw.group_members } : {}),
        ...(strOrNull(raw.group_id) ? { groupId: str(raw.group_id) } : {}),
        ...(Array.isArray(raw.flags) ? { flags: raw.flags, flagList: parseFlags(raw.flags) } : {}),
        details,
        // The artifact row the event came from (`details.source_record` {output, row_index}) and
        // its type: the viewer's "원본 아티팩트 열기" pivot.
        ...(isRecord(details.source_record) ? { sourceRecord: details.source_record } : {}),
        ...(sourceType ? { sourceArtifactType: sourceType } : {}),
      },
    );
  },
  columns: [
    {
      ...col.timestamp(190, ["analysis", "compact", "source"]),
      // 시각 tooltip: the formatted time plus what it means ("수정", "실행 3회차", …) and its zone note.
      tooltip: (r) => {
        const time = r.timestamp ? formatEvidenceTime(r.timestamp, currentTimezone()) : "";
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
    col.field(
      "tsKind",
      "시각 종류",
      110,
      ["analysis", "compact", "source"],
      (r) => str(r.fields.tsKind) || null,
      {
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
      },
    ),
    // 영역·유형: Korean name of the source artifact type; the raw ids in the tooltip.
    col.field("area", "영역·유형", 150, ["analysis", "compact"], (r) => str(r.fields.area) || null, {
      tooltip: (r) => [str(r.fields.sourceArtifactType), r.artifactType ?? ""].filter(Boolean).join(" · "),
    }),
    // 대상: the thing the event is about (file name, executable, URL host + path, key tail).
    col.field("target", "대상", 320, ["analysis", "compact", "source"], (r) => str(r.fields.target) || null, {
      minWidth: 160,
      tooltip: (r) => str(r.fields.targetFull),
    }),
    // 상세: one kind-specific line (catalogue family facts; event logs: their summary).
    col.field("detail", "상세", 320, ["analysis"], (r) => str(r.fields.detail) || null, { minWidth: 160 }),
    // 출처 N: sources folded into this row (display groups).
    col.field(
      "sourceCount",
      "출처 수",
      70,
      ["analysis"],
      (r) =>
        typeof r.fields.sourceCount === "number" && r.fields.sourceCount > 1 ? r.fields.sourceCount : null,
      {
        align: "right",
        filterKind: "number",
        format: (r) =>
          typeof r.fields.sourceCount === "number" && r.fields.sourceCount > 1
            ? `출처 ${r.fields.sourceCount}`
            : "",
        tooltip: (r) => {
          const sources = Array.isArray(r.fields.groupSources)
            ? (r.fields.groupSources as Array<{ artifactType: string; path: string }>)
            : [];
          return sources.map((s) => `${timelineAreaLabel(s.artifactType)} — ${s.path}`).join("\n");
        },
        render: sourceCountCell,
      },
    ),
    { ...flagsColumn(["analysis"]), width: 150 },
    // 출처 행: the source file without the acquisition root (last folders + name); full path on hover.
    col.field("sourceRow", "출처 행", 260, ["analysis", "source"], (r) => str(r.fields.sourceRow) || null, {
      minWidth: 140,
      tooltip: (r) => r.sourcePath ?? "",
    }),
    // Selectable, off by default: summary, source, raw event id, review mark, full path.
    { ...col.title("요약", 380), presets: ["compact", "source", "axiom"] },
    col.field("source", "출처", 90, [], (r) => r.provider),
    col.field("eventType", "이벤트", 160, [], (r) => r.artifactType),
    col.review(),
    col.path(420, ["source"]),
  ],
};
