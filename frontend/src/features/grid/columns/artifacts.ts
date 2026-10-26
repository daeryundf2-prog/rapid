import { fetchArtifactsPage, locateArtifactRow } from "../../../api/collections";
import { clipValue, flatValue } from "../../../utils/flatValue";
import { formatGridTime } from "../../../utils/time";
import { artifactTypeLabel } from "../../filters/typeLabels";
import {
  type CatalogFamily,
  familyForKind,
  familyForTypes,
  majorityFamilyForTypes,
} from "../../flags/catalog";
import { parseFlags } from "../../flags/flags";
import { kindsForCategory } from "../../tree/categories";
import { serverPathFilter } from "../gridUtils";
import type { CollectionDef, ColumnSpec } from "../types";
import { labelledCell } from "../valueLabels";
import { recordHighlight, registryCellKindLabel, summarizeArtifact } from "./artifactSummary";
import {
  col,
  currentTimezone,
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
import {
  familyColumnId,
  familyLayout,
  familyWidthPriority,
  flagsColumn,
  mixedSummaryColumns,
} from "./families";
import { mismatchDirectionLabel } from "./files";
import { typeChipCell } from "./StatusCells";

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

/** An ISO 8601 date-time as the parsers write it ("2026-10-13T01:51:39.506937+00:00"). */
const ISO_DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$/;

/** Reason on headers of list-valued columns (the server sorts scalars only). */
export const SORT_LIST_REASON = "목록 값은 전체 정렬을 지원하지 않습니다";

/** eventlog message keys in display order (the summary shows the first present one). */
export const EVENT_MESSAGE_KEYS = ["message", "rendered_message", "event_message"];

/** 유형: a chip (the web-log node filters on it server-side, `artifact_type=`). */
const typeColumn = col.field("type", "유형", 160, ["analysis", "compact"], (r) => r.artifactType, {
  render: typeChipCell,
  // The chip reads the Korean type name; the hover keeps the exact artifact_type id.
  tooltip: (r) => {
    const id = r.artifactType ?? "";
    const label = id ? artifactTypeLabel(id) : null;
    return label ? `${label} (${id})` : id;
  },
});
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
const timeColumn: ColumnSpec = { ...col.timestamp(), sortKey: "timestamp" };
const tail = [
  col.field(
    "provider",
    "파서",
    130,
    ["analysis", "source"],
    (r) => r.provider,
    labelledCell("provider", (r) => r.provider),
  ),
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
  /** ISO timestamp: shown in the display timezone, filtered from/to. */
  time?: boolean;
  /** Presets the column is visible in (default analysis + axiom). */
  presets?: ColumnSpec["presets"];
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

/** Column over one (or the first present of several) `details` keys; server-sorted on the first key. */
export function kindColumn(def: KindColumnDef): ColumnSpec {
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
    presets: def.presets ?? ["analysis", "axiom"],
    ...(def.mono ? { mono: true } : {}),
    ...(def.time
      ? { filterKind: "time" as const }
      : def.number || def.bytes
        ? { filterKind: "number" as const }
        : {}),
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
      // Time columns — and any ISO date-time value — read in the display zone (viewer redesign §2).
      if (
        (def.time && (typeof v === "string" || typeof v === "number")) ||
        (typeof v === "string" && ISO_DATETIME.test(v))
      ) {
        return formatGridTime(v, currentTimezone());
      }
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

/** "REG_SZ · 24 B" for value cells, else the value type / cell kind as written. */
function registryValueKind(details: Record<string, unknown>): string {
  const detail = registryCellDetail(details);
  if (detail) return detail;
  const t = details.value_type;
  return typeof t === "number" ? (REG_VALUE_TYPES[t] ?? `유형 ${t}`) : flatValue(t);
}

/** First volume of a prefetch row: the reference's device path, else volumes[0] (device · serial). */
function prefetchVolume(details: Record<string, unknown>): string {
  if (typeof details.volume_device_path === "string" && details.volume_device_path) {
    return details.volume_device_path;
  }
  const first = Array.isArray(details.volumes) ? details.volumes[0] : undefined;
  if (!isRecord(first)) return "";
  return [flatValue(first.volume_device_path), flatValue(first.volume_serial_number)]
    .filter(Boolean)
    .join(" · ");
}

const SAM_COLUMNS: KindColumnDef[] = [
  {
    header: "계정",
    keys: ["user_name", "user_name_candidate", "group_name", "group_name_candidate"],
    width: 180,
  },
  {
    header: "RID",
    keys: ["rid", "rid_decimal", "alias_rid_decimal"],
    width: 80,
    number: true,
    tooltip: (d) => {
      const dec = flatValue(d.rid ?? d.rid_decimal ?? d.alias_rid_decimal);
      const hex = flatValue(d.rid_hex || d.alias_rid_hex);
      return [dec, hex ? `(${hex})` : "", flatValue(d.sid)].filter(Boolean).join(" ");
    },
  },
  { header: "마지막 로그온", keys: ["last_logon_at"], width: 190, time: true },
  { header: "로그온 수", keys: ["logon_count"], width: 90, number: true },
  {
    header: "역할",
    keys: ["candidate_role", "account_type_hint", "well_known_account_ko"],
    width: 140,
    presets: [],
  },
  {
    header: "마지막 기록",
    keys: ["key_last_written_at", "last_written_at"],
    width: 190,
    time: true,
    presets: [],
  },
];

/**
 * Column sets of artifact-type families (viewer redesign §7): used when the grid's 유형 filter
 * selects types of one family only (tree nodes such as 다운로드 · USB · SAM 계정 · 예약 작업).
 */
export const TYPE_FAMILY_COLUMNS: Record<string, { types: readonly string[]; columns: KindColumnDef[] }> = {
  "browser-visit": {
    types: ["browser-visit", "browser-history"],
    columns: [
      { header: "URL", keys: ["url"], width: 360 },
      { header: "제목", keys: ["title"], width: 220 },
      { header: "방문 수", keys: ["visit_count"], width: 80, number: true },
      { header: "전환", keys: ["transition_core", "transition"], width: 110 },
    ],
  },
  "browser-download": {
    types: ["browser-download"],
    columns: [
      { header: "URL", keys: ["source_url", "url", "tab_url"], width: 320 },
      { header: "대상 경로", keys: ["target_path", "current_path"], width: 280 },
      { header: "크기", keys: ["total_bytes", "received_bytes"], width: 100, bytes: true },
      { header: "상태", keys: ["state_name", "state"], width: 100 },
    ],
  },
  usb: {
    types: ["windows-usb-device", "registry-usb"],
    columns: [
      { header: "장치명", keys: ["friendly_name", "product"], width: 220 },
      { header: "시리얼", keys: ["serial_number", "usb_serial_number"], width: 180, mono: true },
      {
        header: "VID/PID",
        keys: ["vid", "pid"],
        width: 120,
        mono: true,
        get: (d) => [flatValue(d.vid), flatValue(d.pid)].filter(Boolean).join("/"),
      },
      { header: "마지막 연결", keys: ["last_arrival_at"], width: 190, time: true },
    ],
  },
  sam: {
    types: [
      "windows-sam-account",
      "windows-sam-account-candidate",
      "windows-sam-group",
      "windows-sam-group-candidate",
    ],
    columns: SAM_COLUMNS,
  },
  task: {
    types: ["task-scheduler-task"],
    columns: [
      { header: "작업 경로", keys: ["task_uri"], width: 260 },
      { header: "명령", keys: ["command", "command_line"], width: 280, mono: true },
      { header: "작성자", keys: ["author"], width: 140 },
      { header: "트리거", keys: ["trigger_types"], width: 160, list: true },
    ],
  },
};

/**
 * The catalogue family of the grid (viewer-families U-F3): the one family of the 유형 filter's
 * types, else the one family claiming the kind. Mixed kinds have none (KIND_COLUMNS fallback).
 */
export function resolveArtifactFamily(
  kind: string | undefined,
  types?: readonly string[],
): CatalogFamily | undefined {
  // Several types of one kind: the family holding most of their rows (C6), else the mixed layout.
  return familyForTypes(types) ?? (types?.length ? majorityFamilyForTypes(kind, types) : familyForKind(kind));
}

/** The type family every selected type belongs to (one family only), else undefined. */
export function artifactTypeFamily(types: readonly string[] | undefined): string | undefined {
  if (!types?.length) return undefined;
  const catalogued = familyForTypes(types);
  if (catalogued) return `catalog:${catalogued.id}`;
  for (const [family, def] of Object.entries(TYPE_FAMILY_COLUMNS)) {
    if (types.every((type) => def.types.includes(type))) return family;
  }
  return undefined;
}

/** Korean reading of a messenger row's `direction` (every app's raw spelling). */
export const MESSENGER_DIRECTION_KO: Readonly<Record<string, string>> = {
  outgoing: "발신",
  sent: "발신",
  out: "발신",
  발신: "발신",
  incoming: "수신",
  received: "수신",
  in: "수신",
  수신: "수신",
  unknown: "불명",
  불명: "불명",
};

export const KIND_COLUMNS: Record<string, KindColumnDef[]> = {
  eventlog: [
    { header: "레벨", keys: ["level"], width: 80 },
    { header: "컴퓨터", keys: ["computer"], width: 160 },
    { header: "사용자", keys: ["user_name"], width: 140 },
  ],
  // Prefetch: 실행 파일 · 실행 횟수 · 최근 실행 · 볼륨.
  "windows-prefetch": [
    { header: "실행 파일", keys: ["executable_hint", "header_executable_name"], width: 200 },
    { header: "실행 횟수", keys: ["run_count"], width: 90, number: true },
    { header: "최근 실행", keys: ["last_run_at"], width: 190, time: true },
    {
      header: "볼륨",
      keys: ["volume_device_path", "volumes"],
      width: 220,
      get: prefetchVolume,
      unsortable: true,
      mono: true,
    },
    { header: "참조 경로", keys: ["referenced_path"], width: 320, presets: [] },
    // prefetch-reference rows (most of the kind) carry coverage_status, not the parse status.
    { header: "파싱 상태", keys: ["prefetch_parse_status", "coverage_status"], width: 120, presets: [] },
  ],
  // Registry: 키 경로 · 값 이름 · 값 종류 · 마지막 기록 (the hive cell details stay one click away).
  "windows-registry": [
    {
      header: "키 경로",
      keys: ["key", "key_path", "source_key_path", "usb_key_path"],
      width: 320,
      mono: true,
    },
    { header: "값 이름", keys: ["value_name", "name", "value_names"], width: 200 },
    {
      header: "값 종류",
      keys: ["value_type", "cell_kind", "value_data_size", "subkey_count", "value_count"],
      width: 150,
      get: registryValueKind,
      unsortable: true,
    },
    {
      header: "마지막 기록",
      keys: ["key_last_written_at", "last_written_at", "usb_key_last_written_at"],
      width: 190,
      time: true,
    },
    { header: "하이브", keys: ["hive_name", "hive_hint"], width: 120, presets: [] },
    { header: "셀 오프셋", keys: ["cell_offset"], width: 100, number: true, mono: true, presets: [] },
  ],
  // ShellBags: 경로 · MRU · 키 기록 시각.
  "windows-shellbags": [
    {
      header: "경로",
      keys: ["shell_path", "folder_path", "shellbag_path_candidates"],
      width: 320,
      get: (d) => firstValue(d, ["shell_path", "folder_path"]) ?? firstOfList("shellbag_path_candidates")(d),
      unsortable: true,
    },
    { header: "MRU", keys: ["mru_position"], width: 70, number: true },
    { header: "키 기록 시각", keys: ["key_last_written_at", "last_written_at"], width: 190, time: true },
    { header: "키 경로", keys: ["key_path", "source_key_path", "key"], width: 260, presets: [] },
    { header: "신뢰도", keys: ["parser_confidence"], width: 90, presets: [] },
  ],
  // LNK / Jump List: 대상 · 대상 수정 · 볼륨 시리얼 · 머신 ID.
  "recent-files": [
    { header: "대상", keys: ["target_path", "destlist_path", "entry_hint"], width: 300 },
    { header: "대상 수정", keys: ["target_modified_at"], width: 190, time: true },
    { header: "볼륨 시리얼", keys: ["volume_serial_number"], width: 120, mono: true },
    { header: "머신 ID", keys: ["tracker_machine_id", "destlist_hostname"], width: 140, mono: true },
    { header: "대상 크기", keys: ["target_file_size"], width: 100, bytes: true, presets: [] },
    { header: "파싱 상태", keys: ["lnk_parse_status"], width: 120, presets: [] },
    { header: "작업 폴더", keys: ["working_dir"], width: 200, presets: [] },
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
  // Accounts (SAM): 계정 · RID · 마지막 로그온 · 로그온 수.
  "windows-os-account": SAM_COLUMNS,
  "windows-filesystem": [
    { header: "감지 서명", keys: ["detected_signature_kind"], width: 130 },
    { header: "기대 확장자", keys: ["expected_extensions"], width: 140, list: true },
    // Same `mismatch_direction` as files.json `file_signature` (files 시그니처 column).
    {
      header: "불일치 방향",
      keys: ["mismatch_direction"],
      width: 170,
      display: (value) => (typeof value === "string" ? mismatchDirectionLabel(value) : ""),
      tooltip: (d) => (typeof d.mismatch_direction === "string" ? d.mismatch_direction : ""),
    },
    { header: "크기", keys: ["source_size"], width: 100, bytes: true },
    { header: "수정", keys: ["modified_at"], width: 170 },
    { header: "위험", keys: ["risk_flags"], width: 220, list: true },
  ],
  // Browser (all types): the visit columns; downloads etc. via the 유형 filter (TYPE_FAMILY_COLUMNS).
  browser: [
    { header: "URL", keys: ["url", "source_url", "tab_url"], width: 360 },
    { header: "제목", keys: ["title"], width: 220 },
    { header: "방문 수", keys: ["visit_count"], width: 80, number: true },
    { header: "전환", keys: ["transition_core", "transition"], width: 110 },
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
  // 데스크톱 메신저 group (messages · contacts · attachments mixed, r2 console fix m7): the
  // conversation facts every row type shares; 방향 reads 발신/수신/불명.
  "windows-messenger": [
    { header: "앱", keys: ["service", "app"], width: 150 },
    { header: "대화방", keys: ["conversation_title", "conversation_id"], width: 200 },
    { header: "발화자·이름", keys: ["sender", "contact_name", "display_name"], width: 160 },
    {
      header: "방향",
      keys: ["direction"],
      width: 70,
      display: (value) => MESSENGER_DIRECTION_KO[String(value ?? "").toLowerCase()] ?? String(value ?? ""),
      tooltip: (details) => (details.direction ? `원래 값: ${String(details.direction)}` : ""),
    },
    { header: "본문·파일", keys: ["message_text_preview", "message_text", "file_name"], width: 320 },
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

/**
 * Generic artifact layout (all artifacts, category nodes, kinds without a layout), visual-polish
 * S4: 시각 · 유형 · 항목 · 경로 · 선별. The summary text stays one click away in the column menu.
 */
const defaultColumns = (): ColumnSpec[] => [
  // Default width = minimum width: 항목 takes the slack (DataGrid fitColumnWidths); a narrow
  // grid hides 경로 → 선별 → 시각 → 유형 instead of truncating everything (ARTIFACT_PRIORITY).
  // 시각 is in 출처 중심 too: a source review still needs the time (review B2-6).
  { ...timeColumn, presets: ["analysis", "compact", "source"] },
  // 130px: the colour dot + ~14 characters ("cloud-messaging") without an ellipsis.
  { ...typeColumn, width: 130, minWidth: 130 },
  { ...col.title("항목", 220), minWidth: 220 },
  // 특이사항 (U-F4): hidden while no loaded row carries a flag (empty default column, ARTIFACT_PRIORITY).
  flagsColumn(["analysis", "compact"]),
  col.path(200, ["analysis", "source"]),
  { ...col.review(), width: 88, minWidth: 88 },
  quietDetailColumn,
  // 파서 moves to 출처 중심 here: the default shows exactly the five columns above.
  ...tail
    .filter((column) => column.id !== "path")
    .map((column): ColumnSpec => (column.id === "provider" ? { ...column, presets: ["source"] } : column)),
];

/**
 * Mixed-family grid (U-F8, AXIOM's 혼합 아티팩트 격자): every artifact, a category / domain node
 * over several kinds, or a 유형 filter spanning families. Instead of one family's columns, four
 * summary columns whose cells carry their own label above the value (the row's family decides
 * what 주요 / 지원 / 추가 / 시각 are); one family resolves to its catalogue layout instead.
 */
export function isMixedGrid(kind: string | undefined, types?: readonly string[]): boolean {
  if (resolveArtifactFamily(kind, types)) return false;
  return !kind || (types?.length ?? 0) > 1;
}

const mixedColumns = (): ColumnSpec[] => [
  { ...typeColumn, width: 130, minWidth: 130 },
  { ...col.title("항목", 220), minWidth: 200 },
  flagsColumn(["analysis", "compact"]),
  ...mixedSummaryColumns(),
  { ...col.review(), width: 88, minWidth: 88 },
  { ...timeColumn, presets: ["source"] },
  col.path(200, ["source"]),
  quietDetailColumn,
  ...tail
    .filter((column) => column.id !== "path")
    .map((column): ColumnSpec => (column.id === "provider" ? { ...column, presets: ["source"] } : column)),
];

/** Mixed layout priority: 항목 > 주요 > 특이사항 > 유형 > 시각 > 지원 > 추가 > 선별. */
export const MIXED_PRIORITY = [
  "title",
  "sum:main",
  "flags",
  "type",
  "sum:time",
  "sum:support",
  "sum:extra",
  "review",
] as const;

/** Generic artifact layout, highest priority first: 항목 > 특이사항 > 유형 > 시각 > 선별 > 경로. */
export const ARTIFACT_PRIORITY = ["title", "flags", "type", "timestamp", "review", "path"] as const;

/**
 * Responsive layouts: the generic one and every catalogue family layout (empty core columns go
 * first, then the lowest priority by width); KIND_COLUMNS fallbacks keep their own columns.
 */
export function artifactWidthPriority(
  kind: string | undefined,
  types?: readonly string[],
): readonly string[] | undefined {
  const catalogued = resolveArtifactFamily(kind, types);
  if (catalogued) return familyWidthPriority(catalogued);
  if (isMixedGrid(kind, types) && !(kind && KIND_COLUMNS[kind])) return MIXED_PRIORITY;
  if (kind && types?.length && artifactTypeFamily(types)) return undefined;
  return kind && (kind === "eventlog" || KIND_COLUMNS[kind]) ? undefined : ARTIFACT_PRIORITY;
}

/** Default column set of one artifact kind (plan §4.3); other kinds keep the generic set. */
export function artifactColumnsForKind(kind: string | undefined, types?: readonly string[]): ColumnSpec[] {
  const catalogued = resolveArtifactFamily(kind, types);
  if (catalogued) {
    return familyLayout(catalogued, {
      title: col.title("항목", 240),
      review: col.review(),
      type: typeColumn,
      // eventlog keeps its 메시지 column (sorts on the key the cells show), off by default.
      rest: [
        { ...timeColumn, presets: [] },
        catalogued.id === "eventlog" ? { ...messageColumn, presets: [] } : quietDetailColumn,
        // The catalogue sets the examiner's default columns: 파서 stays in 원본 preset / 열 선택.
        ...tail.map((column) => ({ ...column, presets: column.presets.filter((p) => p !== "analysis") })),
      ],
    });
  }
  const family = kind ? artifactTypeFamily(types) : undefined;
  const defs = family ? TYPE_FAMILY_COLUMNS[family]?.columns : kind ? KIND_COLUMNS[kind] : undefined;
  if (kind === "eventlog" && !family) {
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
  if (!defs) return isMixedGrid(kind, types) ? mixedColumns() : defaultColumns();
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
      query.artifactTypes,
      { ids: query.flags, grade: query.flagGrade, fields: query.fields, conditions: query.rowConditions },
      { names: query.channels, groups: query.channelGroups },
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
        // 특이사항 (U-F4): raw API value + the parsed list the cells read.
        ...(Array.isArray(raw.flags) ? { flags: raw.flags, flagList: parseFlags(raw.flags) } : {}),
        details,
      },
    );
  },
  columns: defaultColumns(),
  columnsFor: (ref, types) => artifactColumnsForKind(ref.kind, types),
  widthPriority: (ref, types) => artifactWidthPriority(ref.kind, types),
  // A family's core column with no value in any loaded row hides like any empty default column
  // (C-D7/C-E4, plan r7 §3.2 L2): it comes back as soon as a loaded row has a value, and 열 선택
  // lists it as "값이 없어 숨김". Only the leading time column stays (the row's place in time).
  keepWhenEmpty: (ref, types) => {
    const family = resolveArtifactFamily(ref.kind, types);
    const lead = family?.core_columns[0];
    return lead?.format === "time" ? [familyColumnId(lead.key)] : [];
  },
  locate: (runId, ref, sort, recordIndex, signal) =>
    ref.kind
      ? locateArtifactRow(runId, ref.kind, sort, recordIndex, signal)
      : Promise.resolve({ status: "ready", position: null }),
};

/** details key → header of the kind's DEFAULT column that already shows it (meta tab "열로 표시"). */
export function defaultFieldHeaders(
  kind: string | undefined,
  visibleIds?: readonly string[] | null,
  types?: readonly string[],
): Map<string, string> {
  const out = new Map<string, string>();
  const visible = visibleIds ? new Set(visibleIds) : null;
  for (const column of artifactColumnsForKind(kind, types)) {
    // Only columns actually on screen (current preset + visibility); without a mounted grid the
    // analysis preset decides.
    const shown = visible ? visible.has(column.id) : column.presets.includes("analysis");
    if (!shown) continue;
    for (const key of column.fieldKeys ?? []) if (!out.has(key)) out.set(key, column.header);
  }
  return out;
}
