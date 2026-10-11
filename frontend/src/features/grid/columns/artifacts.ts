import { fetchArtifactsPage } from "../../../api/collections";
import { clipValue, flatValue } from "../../../utils/flatValue";
import { kindsForCategory } from "../../tree/categories";
import { serverPathFilter } from "../gridUtils";
import type { CollectionDef, ColumnSpec } from "../types";
import { recordHighlight, registryCellKindLabel, summarizeArtifact } from "./artifactSummary";
import {
  col,
  fieldStr,
  formatBytes,
  isRecord,
  makeRef,
  makeRow,
  recoveryFields,
  sha256Of,
  str,
  strOrNull,
} from "./common";

/** Row time = first of these details keys. Same order as the server's `sort=timestamp` (plan §4.1). */
export const TIME_KEYS = [
  "timestamp",
  "time",
  "time_created",
  "last_run_at",
  "last_run_time",
  "last_modified",
  "modified_at",
  "key_last_written_at",
  "last_written_at",
  "event_time",
  "normalized_time",
  "created_at",
  "target_modified_at",
];

/** First non-empty scalar among `keys` (lists / objects are skipped, like the server's timestamp sort). */
function firstOf(details: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = details[key];
    if (typeof value !== "string" && typeof value !== "number") continue;
    const text = strOrNull(value);
    if (text) return text;
  }
  return null;
}

/** Reason on headers of list-valued columns (the server sorts scalars only). */
export const SORT_LIST_REASON = "목록 값은 전체 정렬을 지원하지 않습니다";

/** eventlog message keys in display order (the summary shows the first present one). */
export const EVENT_MESSAGE_KEYS = ["message", "rendered_message", "event_message"];

const typeColumn = col.field("type", "유형", 160, ["analysis", "compact"], (r) => r.artifactType);
const eventColumns = [
  col.field("eventId", "이벤트ID", 90, ["analysis", "compact"], (r) => fieldStr(r, "eventId"), {
    sortKey: "details.event_id",
    fieldKeys: ["event_id"],
  }),
  col.field("channel", "채널", 120, ["analysis", "compact"], (r) => fieldStr(r, "channel")),
];
const messageColumn = col.field("detail", "메시지", 420, ["analysis"], (r) => fieldStr(r, "detail"), {
  fieldKeys: EVENT_MESSAGE_KEYS,
  // The grid picks the first of these present in the loaded rows (the key the cells show first).
  sortCandidates: EVENT_MESSAGE_KEYS,
  sortHintFor: messageSortHint,
  sortKey: "details.event_message",
  sortHint: messageSortHint("event_message"),
});

/** The cells strip the leading "provider=… | channel=…" segments of event_message: say "원문". */
export function messageSortHint(key: string): string {
  return key === "event_message" ? "메시지 정렬 (원문 event_message 기준)" : `메시지 정렬 (${key} 기준)`;
}
const detailColumn = col.field("detail", "내용", 320, ["analysis"], (r) => fieldStr(r, "detail"));
/** Kind layouts keep the summary column, off by default (the kind columns carry the detail). */
const quietDetailColumn: ColumnSpec = { ...detailColumn, presets: [] };
/** Server-sorted on `timestamp` (first TIME_KEYS value, the same rule as the server). */
const timeColumn: ColumnSpec = { ...col.timestamp(170), sortKey: "timestamp" };
const tail = [
  col.field("provider", "파서", 130, ["analysis", "source"], (r) => r.provider),
  col.field("rules", "탐지 규칙", 160, ["source"], (r) => fieldStr(r, "matchedRules")),
  col.field("supported", "지원", 70, ["source"], (r) => (r.fields.supported === false ? "미지원" : "")),
  col.path(420, ["source"]),
  col.sha256(),
];

// ---- kind columns (plan artifact-columns §4.3) ---------------------------------

export interface KindColumnDef {
  header: string;
  /**
   * details keys; the first non-empty one is shown. The server sorts on the first key (several keys:
   * the sort button names it, "실행 파일 정렬 (executable_hint 기준)").
   */
  keys: string[];
  width?: number;
  /** Custom value (e.g. width×height); still sorted on the first key unless `unsortable`. */
  get?: (details: Record<string, unknown>) => unknown;
  /** Truly computed (a list element, several keys combined): no server sort. */
  unsortable?: boolean;
  /** The value is a list in live data: no server sort (reason SORT_LIST_REASON). */
  list?: boolean;
  /** Display text from the read value (default: flat text / bytes). */
  display?: (value: unknown, details: Record<string, unknown>) => string;
  /** Cell tooltip (default: the display text). */
  tooltip?: (details: Record<string, unknown>) => string;
  bytes?: boolean;
  mono?: boolean;
  number?: boolean;
}

function detailsOf(row: { fields: Record<string, unknown> }): Record<string, unknown> {
  return isRecord(row.fields.details) ? row.fields.details : {};
}

function firstValue(details: Record<string, unknown>, keys: string[]): unknown {
  for (const key of keys) {
    const v = details[key];
    if (v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && v.length === 0)) return v;
  }
  return undefined;
}

function kindColumn(def: KindColumnDef): ColumnSpec {
  const read = (row: { fields: Record<string, unknown> }) =>
    def.get ? def.get(detailsOf(row)) : firstValue(detailsOf(row), def.keys);
  const sortable = !def.unsortable && !def.list;
  const first = def.keys[0] as string;
  const named = sortable && (def.keys.length > 1 || def.get !== undefined);
  return {
    id: `d:${def.keys[0]}`,
    header: def.header,
    width: def.width ?? 150,
    minWidth: 60,
    presets: ["analysis", "axiom"],
    ...(def.mono ? { mono: true } : {}),
    ...(def.number || def.bytes ? { align: "right" as const } : {}),
    ...(sortable ? { sortKey: `details.${first}` } : {}),
    ...(named ? { sortHint: `${def.header} 정렬 (${first} 기준)` } : {}),
    ...(def.list ? { unsortableReason: SORT_LIST_REASON } : {}),
    fieldKeys: def.keys,
    value: (row) => {
      const v = read(row);
      return typeof v === "number" ? v : flatValue(v);
    },
    format: (row) => {
      const v = read(row);
      if (def.display) return def.display(v, detailsOf(row));
      if (def.bytes && typeof v === "number") return formatBytes(v);
      return clipValue(flatValue(v), 300);
    },
    ...(def.tooltip
      ? { tooltip: (row) => (def.tooltip as (d: Record<string, unknown>) => string)(detailsOf(row)) }
      : {}),
  };
}

const firstOfList = (key: string) => (details: Record<string, unknown>) => {
  const list = details[key];
  return Array.isArray(list) ? list[0] : list;
};

export { registryCellKindLabel };

const REG_VALUE_TYPES: Record<number, string> = {
  0: "REG_NONE",
  1: "REG_SZ",
  2: "REG_EXPAND_SZ",
  3: "REG_BINARY",
  4: "REG_DWORD",
  5: "REG_DWORD_BIG_ENDIAN",
  6: "REG_LINK",
  7: "REG_MULTI_SZ",
  8: "REG_RESOURCE_LIST",
  11: "REG_QWORD",
};

/** 세부: value cells "REG_SZ · 24 B", key cells "하위키 2 · 값 5". */
export function registryCellDetail(details: Record<string, unknown>): string {
  const kind = registryCellKindLabel(details.cell_kind);
  if (kind === "값") {
    const t = details.value_type;
    const type = typeof t === "number" ? (REG_VALUE_TYPES[t] ?? `유형 ${t}`) : str(t);
    const size = details.value_data_size;
    return [type, typeof size === "number" ? `${size.toLocaleString("ko-KR")} B` : ""]
      .filter(Boolean)
      .join(" · ");
  }
  if (kind === "키") {
    const sub = details.subkey_count;
    const values = details.value_count;
    return [typeof sub === "number" ? `하위키 ${sub}` : "", typeof values === "number" ? `값 ${values}` : ""]
      .filter(Boolean)
      .join(" · ");
  }
  return str(details.value_type);
}

export const KIND_COLUMNS: Record<string, KindColumnDef[]> = {
  eventlog: [
    { header: "레벨", keys: ["level"], width: 80 },
    { header: "컴퓨터", keys: ["computer"], width: 160 },
    { header: "사용자", keys: ["user_name"], width: 140 },
  ],
  "windows-prefetch": [
    { header: "실행 파일", keys: ["executable_hint", "header_executable_name"], width: 200 },
    { header: "실행 횟수", keys: ["run_count"], width: 90, number: true },
    { header: "최근 실행", keys: ["last_run_at"], width: 170 },
    { header: "참조 경로", keys: ["referenced_path"], width: 320 },
    // prefetch-reference rows (most of the kind) carry coverage_status, not the parse status.
    { header: "파싱 상태", keys: ["prefetch_parse_status", "coverage_status"], width: 120 },
  ],
  "windows-registry": [
    { header: "하이브", keys: ["hive_name"], width: 120 },
    {
      header: "셀 종류",
      keys: ["cell_kind"],
      width: 80,
      display: (v) => registryCellKindLabel(v),
      tooltip: (d) => flatValue(d.cell_kind),
    },
    { header: "이름", keys: ["name"], width: 200 },
    {
      header: "세부",
      keys: ["value_type", "value_data_size", "subkey_count", "value_count"],
      width: 170,
      get: registryCellDetail,
      unsortable: true,
    },
    { header: "마지막 기록", keys: ["last_written_at"], width: 170 },
    { header: "셀 오프셋", keys: ["cell_offset"], width: 100, number: true, mono: true },
  ],
  "windows-shellbags": [
    {
      header: "경로 후보",
      keys: ["shellbag_path_candidates"],
      width: 280,
      get: firstOfList("shellbag_path_candidates"),
      list: true,
    },
    { header: "키 경로", keys: ["source_key_path"], width: 260 },
    { header: "마지막 기록", keys: ["key_last_written_at"], width: 170 },
    { header: "신뢰도", keys: ["parser_confidence"], width: 90 },
  ],
  "recent-files": [
    { header: "대상 경로", keys: ["target_path"], width: 300 },
    { header: "대상 수정", keys: ["target_modified_at"], width: 170 },
    { header: "대상 크기", keys: ["target_file_size"], width: 100, bytes: true },
    { header: "파싱 상태", keys: ["lnk_parse_status"], width: 120 },
    { header: "작업 폴더", keys: ["working_dir"], width: 200 },
  ],
  "windows-execution": [
    { header: "실행 경로", keys: ["executable_path"], width: 300 },
    { header: "프로그램", keys: ["program_name"], width: 180 },
    { header: "게시자", keys: ["publisher"], width: 160 },
    { header: "버전", keys: ["version"], width: 100 },
    { header: "SHA-1", keys: ["sha1"], width: 200, mono: true },
    { header: "키 기록", keys: ["key_last_written_at"], width: 170 },
  ],
  // 앱/앱 경로/오류 모듈/이벤트 시각 stay promotable but are not defaults until the WER parser
  // decodes UTF-16 .wer files (their keys are garbled today; QA run-subset7).
  "windows-system": [
    { header: "앱", keys: ["application_name"], width: 180 },
    { header: "앱 경로", keys: ["application_path"], width: 320 },
    { header: "오류 모듈", keys: ["fault_module_name"], width: 160 },
    { header: "이벤트 시각", keys: ["event_time"], width: 170 },
    { header: "보고서 ID", keys: ["report_id"], width: 220, mono: true },
    { header: "크기", keys: ["source_size"], width: 100, bytes: true },
    { header: "수정", keys: ["modified_at"], width: 170 },
  ],
  "windows-os-account": [
    { header: "계정", keys: ["user_name_candidate", "user_name", "group_name_candidate"], width: 180 },
    { header: "역할", keys: ["candidate_role", "account_type_hint"], width: 160 },
    {
      header: "RID",
      keys: ["rid_decimal", "alias_rid_decimal"],
      width: 80,
      number: true,
      tooltip: (d) => {
        const dec = flatValue(d.rid_decimal || d.alias_rid_decimal);
        const hex = flatValue(d.rid_hex || d.alias_rid_hex);
        return [dec, hex ? `(${hex})` : ""].filter(Boolean).join(" ");
      },
    },
    { header: "마지막 기록", keys: ["last_written_at"], width: 170 },
  ],
  "windows-filesystem": [
    { header: "감지 서명", keys: ["detected_signature_kind"], width: 130 },
    { header: "기대 확장자", keys: ["expected_extensions"], width: 140, list: true },
    { header: "크기", keys: ["source_size"], width: 100, bytes: true },
    { header: "수정", keys: ["modified_at"], width: 170 },
    { header: "위험", keys: ["risk_flags"], width: 220, list: true },
  ],
  "media-image": [
    { header: "이름", keys: ["entry_name"], width: 200 },
    {
      header: "크기",
      keys: ["width", "height"],
      width: 110,
      get: (d) =>
        typeof d.width === "number" && typeof d.height === "number" ? `${d.width}×${d.height}` : "",
    },
    { header: "형식", keys: ["source_format"], width: 90 },
    { header: "용량", keys: ["source_size"], width: 100, bytes: true },
    // visual_classification / modified_at are not written by the media parser (QA fill check).
    { header: "유사 묶음", keys: ["similarity_bucket"], width: 120 },
  ],
  // Mixed rows (mobile-app / -message / -export-source / -correlation-summary): message text, else the app.
  "mobile-export": [
    {
      header: "메시지·앱",
      keys: ["message_text_preview", "message_text", "candidate_value", "app_name"],
      width: 320,
    },
    { header: "앱", keys: ["source_app_identifier", "service", "package", "candidate_kind"], width: 180 },
    { header: "이벤트 유형", keys: ["event_type"], width: 130 },
    { header: "출처 도구", keys: ["source_tool"], width: 130 },
  ],
  "cloud-export": [
    { header: "서비스", keys: ["service"], width: 140 },
    { header: "이벤트 유형", keys: ["event_type"], width: 140 },
    { header: "클라우드", keys: ["cloud_family"], width: 130 },
  ],
  "kakaotalk-windows": [
    { header: "후보 종류", keys: ["candidate_kind"], width: 150 },
    { header: "후보 값", keys: ["candidate_value"], width: 320 },
    { header: "위험 점수", keys: ["risk_score"], width: 90, number: true },
    { header: "원본 오프셋", keys: ["source_offset"], width: 110, number: true, mono: true },
  ],
  "generic-documents": [
    { header: "항목 수", keys: ["entry_count"], width: 90, number: true },
    { header: "암호화 항목", keys: ["encrypted_entry_count"], width: 100, number: true },
    { header: "크기", keys: ["source_size"], width: 100, bytes: true },
    { header: "수정", keys: ["modified_at"], width: 170 },
    { header: "위험", keys: ["risk_flags"], width: 240, list: true },
  ],
};

const defaultColumns = (): ColumnSpec[] => [
  col.title("항목", 320),
  col.review(),
  typeColumn,
  detailColumn,
  timeColumn,
  ...tail,
];

/** Default column set of one artifact kind (plan §4.3); other kinds keep the generic set. */
export function artifactColumnsForKind(kind: string | undefined): ColumnSpec[] {
  const defs = kind ? KIND_COLUMNS[kind] : undefined;
  if (kind === "eventlog") {
    return [
      col.title("이벤트", 320),
      col.review(),
      ...eventColumns,
      ...(defs ?? []).map(kindColumn),
      messageColumn,
      timeColumn,
      typeColumn,
      ...tail,
    ];
  }
  if (!defs) return defaultColumns();
  return [
    col.title("항목", 280),
    col.review(),
    ...defs.map(kindColumn),
    timeColumn,
    typeColumn,
    quietDetailColumn,
    ...tail,
  ];
}

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
      query.ref.kind ? query.sort : undefined,
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
  columns: defaultColumns(),
  columnsFor: (ref) => artifactColumnsForKind(ref.kind),
};

/** details key → header of the kind's DEFAULT column that already shows it (meta tab "열로 표시"). */
export function defaultFieldHeaders(
  kind: string | undefined,
  visibleIds?: readonly string[] | null,
): Map<string, string> {
  const out = new Map<string, string>();
  const visible = visibleIds ? new Set(visibleIds) : null;
  for (const column of artifactColumnsForKind(kind)) {
    // Only columns actually on screen (current preset + visibility); without a mounted grid the
    // analysis preset decides.
    const shown = visible ? visible.has(column.id) : column.presets.includes("analysis");
    if (!shown) continue;
    for (const key of column.fieldKeys ?? []) if (!out.has(key)) out.set(key, column.header);
  }
  return out;
}
