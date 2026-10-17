/**
 * Field sheets (viewer redesign §1): per artifact family, the ordered evidence fields of the
 * record view's 핵심 section — modelled on the field sets examiners know from AXIOM / EZ tools
 * (Event Log: 이벤트 ID · 레벨 · 제공자 · 채널 · 컴퓨터 · 사용자/SID · 로그온 ID · 로그온 유형 ·
 * 출발지 IP …). Keys are the ones the parsers emit (rapid-parsers rapidtriage/artifacts/**,
 * docs/rapidtriage-output-schemas.md); several aliases of one fact are listed together and shown
 * once.
 *
 * Every other key of the record is classified, never dropped:
 *  - 출처 (provenance): source path, container file hashes, record offsets, parser, decode state;
 *  - 기타 필드: anything else, expanded, with a humanised label (raw key as the tooltip);
 *  - 내부 검증 정보(증거 아님): governance/validation keys only (commercial_*, validation_*,
 *    blockers, *_plan*, readiness, grade …) — folded at the bottom.
 */

import type { GridRow } from "../../contracts/collection";
import { flatValue } from "../../utils/flatValue";
import { eventSummaryKo, fieldOf } from "../derived/derivedFields";
import { metaLabel } from "./views/metaLabels";

export type FieldFormat =
  | "text"
  | "time"
  | "eventLevel"
  | "detectionSeverity"
  | "logonType"
  | "sid"
  | "bytes"
  | "number"
  | "mono"
  | "url"
  | "path"
  | "hex";

export interface FieldDef {
  /** details key, or aliases of one fact: the first present one is shown, the others are suppressed. */
  key: string | readonly string[];
  label: string;
  format?: FieldFormat;
  /** Time fields: the kind chip (timestamp kind token, e.g. "event", "run", "last-written"). */
  timeKind?: string;
  /**
   * A value derived from the record when no key is present (EventData names, nested objects).
   * The returned `from` names where it came from (shown in the tooltip, "event_data.TargetLogonId").
   */
  derive?: (fields: Record<string, unknown>) => { value: unknown; from: string } | null;
  /**
   * The field is expected on this record (e.g. 로그온 ID on a 4624): when absent it is still
   * listed, reading "레코드에 없음", so the absence is visible rather than silent.
   */
  expectWhen?: (fields: Record<string, unknown>) => boolean;
}

export interface FieldSheet {
  id: string;
  /** Family name shown above the 핵심 section ("이벤트 로그"). */
  label: string;
  /** Artifact types (exact) this sheet covers. */
  types?: readonly string[];
  /** Type prefixes / suffixes (e.g. "browser-", "-string-candidate"). */
  prefixes?: readonly string[];
  suffixes?: readonly string[];
  /** Artifact kinds (grid `ref.kind`) whose rows use this sheet when the type matches no sheet. */
  kinds?: readonly string[];
  core: readonly FieldDef[];
  /** A name/value map shown as a table under 핵심, always visible (EVTX EventData, registry values). */
  table?: { key: readonly string[]; label: string };
  /** Keys that identify the record for citations, first present wins (EventRecordID, key path …). */
  recordId?: readonly string[];
}

// ---------------------------------------------------------------------------
// EventData helpers
// ---------------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function present(value: unknown): boolean {
  if (value === null || value === undefined || value === "") return false;
  if (Array.isArray(value)) return value.length > 0;
  if (isRecord(value)) return Object.keys(value).length > 0;
  return true;
}

/** EventData (+ UserData) as one map: `event_data` object, else `event_data_values` list. */
export function eventDataOf(fields: Record<string, unknown>): Record<string, unknown> | null {
  for (const key of EVENT_DATA_KEYS) {
    const value = fields[key];
    if (isRecord(value) && Object.keys(value).length) return value;
  }
  return null;
}

/** First EventData value among `names` (case-insensitive). */
function fromEventData(...names: string[]) {
  return (fields: Record<string, unknown>) => {
    const data = eventDataOf(fields);
    if (!data) return null;
    const lower = new Map(Object.entries(data).map(([k, v]) => [k.toLowerCase(), [k, v] as const]));
    for (const name of names) {
      const hit = lower.get(name.toLowerCase());
      if (hit && present(hit[1]) && hit[1] !== "-") return { value: hit[1], from: `event_data.${hit[0]}` };
    }
    return null;
  };
}

/** A nested key (`usb_device.serial`) when the flat key is absent. */
function fromNested(path: string) {
  return (fields: Record<string, unknown>) => {
    const [head, ...rest] = path.split(".");
    let value: unknown = head ? fields[head] : undefined;
    for (const part of rest) value = isRecord(value) ? value[part] : undefined;
    return present(value) && !isRecord(value) ? { value, from: path } : null;
  };
}

function firstOf(
  ...derivers: Array<(fields: Record<string, unknown>) => { value: unknown; from: string } | null>
) {
  return (fields: Record<string, unknown>) => {
    for (const derive of derivers) {
      const hit = derive(fields);
      if (hit) return hit;
    }
    return null;
  };
}

// ---------------------------------------------------------------------------
// Sheets
// ---------------------------------------------------------------------------

const t = (key: FieldDef["key"], label: string, timeKind: string, derive?: FieldDef["derive"]): FieldDef => ({
  key,
  label,
  format: "time",
  timeKind,
  ...(derive ? { derive } : {}),
});

/** EVTX: native rows keep EventData under `data`, triage rows under `event_data`. */
export const EVENT_DATA_KEYS = ["event_data", "data", "user_data", "binxml_event_data_values_by_name"];

const EVENT_CORE: FieldDef[] = [
  { key: ["event_id", "eventId", "EventID"], label: "이벤트 ID", format: "mono" },
  { key: "event_label_ko", label: "한글 이벤트명" },
  { key: ["level", "Level"], label: "레벨", format: "eventLevel" },
  { key: ["provider_name", "ProviderName", "provider"], label: "제공자" },
  { key: ["channel", "Channel"], label: "채널" },
  { key: ["computer", "Computer"], label: "컴퓨터" },
  {
    // Korean summary sentence (axiom-adoption §3.2): a template over the record's own fields.
    key: "summary_ko",
    label: "요약 문장",
    derive: (fields) =>
      fieldOf(fields, "event_id", "eventId", "EventID")
        ? { value: eventSummaryKo(fields), from: "summary_ko" }
        : null,
  },
  { key: ["user_name", "user"], label: "사용자" },
  {
    key: ["user_sid", "sid", "subject_user_sid"],
    label: "사용자 SID",
    format: "sid",
    derive: fromEventData("TargetUserSid", "SubjectUserSid", "UserSid"),
  },
  { key: "subject_user_name", label: "주체 사용자", derive: fromEventData("SubjectUserName") },
  { key: "target_user_name", label: "대상 사용자", derive: fromEventData("TargetUserName") },
  { key: "target_domain_name", label: "대상 도메인", derive: fromEventData("TargetDomainName") },
  {
    key: ["logon_id", "target_logon_id", "subject_logon_id"],
    label: "로그온 ID",
    format: "mono",
    derive: fromEventData("TargetLogonId", "SubjectLogonId", "LogonId"),
    expectWhen: isLogonEvent,
  },
  {
    key: "logon_type",
    label: "로그온 유형",
    format: "logonType",
    derive: fromEventData("LogonType"),
    expectWhen: isLogonEvent,
  },
  { key: ["logon_process_name"], label: "로그온 프로세스", derive: fromEventData("LogonProcessName") },
  {
    key: ["authentication_package_name"],
    label: "인증 패키지",
    derive: fromEventData("AuthenticationPackageName"),
  },
  {
    key: ["source_ip", "ip_address"],
    label: "출발지 IP",
    format: "mono",
    derive: fromEventData("IpAddress", "SourceAddress", "ClientAddress"),
    expectWhen: isLogonEvent,
  },
  { key: ["source_port"], label: "출발지 포트", derive: fromEventData("IpPort", "SourcePort") },
  { key: ["workstation_name"], label: "워크스테이션", derive: fromEventData("WorkstationName") },
  { key: ["destination_ip", "destination_hostname"], label: "목적지", format: "mono" },
  { key: ["destination_port"], label: "목적지 포트" },
  { key: ["status_code"], label: "상태 코드", format: "mono", derive: fromEventData("Status") },
  { key: ["failure_reason"], label: "실패 사유", derive: fromEventData("FailureReason", "SubStatus") },
  {
    key: ["process_name", "new_process_name", "image"],
    label: "프로세스",
    format: "path",
    derive: fromEventData("NewProcessName", "ProcessName", "Image"),
  },
  { key: ["process_id"], label: "프로세스 ID", format: "mono" },
  { key: ["thread_id"], label: "스레드 ID", format: "mono" },
  { key: ["command_line"], label: "명령줄", format: "mono", derive: fromEventData("CommandLine") },
  {
    key: ["parent_process_name"],
    label: "부모 프로세스",
    format: "path",
    derive: fromEventData("ParentProcessName", "ParentImage"),
  },
  {
    key: ["parent_command_line"],
    label: "부모 명령줄",
    format: "mono",
    derive: fromEventData("ParentCommandLine"),
  },
  {
    key: ["script_block_text"],
    label: "스크립트 블록",
    format: "mono",
    derive: fromEventData("ScriptBlockText"),
  },
  { key: ["service_name"], label: "서비스 이름", derive: fromEventData("ServiceName") },
  {
    key: ["service_file_name", "service_image_path", "image_path"],
    label: "서비스 경로",
    format: "path",
    derive: fromEventData("ImagePath", "ServiceFileName"),
  },
  {
    key: ["service_account_name"],
    label: "서비스 계정",
    derive: fromEventData("AccountName", "ServiceAccount"),
  },
  { key: ["task_name"], label: "예약 작업", derive: fromEventData("TaskName") },
  { key: ["share_name", "relative_target_name"], label: "공유/대상", format: "path" },
  {
    key: ["target_object", "query_name", "image_loaded", "url", "remote_name", "local_file"],
    label: "대상 개체",
    format: "mono",
  },
  { key: ["device_instance_id", "device_id"], label: "장치 ID", format: "mono" },
  { key: ["document_name", "printer_name"], label: "인쇄 문서/프린터" },
  t(["event_created_at", "timestamp", "time_created"], "생성 시각", "event"),
  { key: ["record_id", "event_record_id", "EventRecordID"], label: "레코드 ID", format: "mono" },
  { key: ["task"], label: "작업(Task)" },
  { key: ["opcode"], label: "연산 코드(Opcode)" },
  { key: ["keywords"], label: "키워드", format: "mono" },
  {
    key: ["rendered_message", "message", "event_message", "event_description", "detail"],
    label: "렌더된 메시지",
  },
  { key: ["rule"], label: "규칙(이벤트)", derive: fromNested("rule.title") },
  { key: ["evtx_record_state"], label: "레코드 상태" },
  { key: ["evtx_record_id_position"], label: "레코드 번호 위치" },
  { key: ["duplicate_of_live_record"], label: "할당 레코드의 중복" },
  { key: ["event_data_key_status"], label: "EventData 이름 상태" },
  { key: ["timestamp_status"], label: "시각 상태" },
];

const DETECTION_CORE: FieldDef[] = [
  {
    key: ["rule_title", "rule_name", "matchedRules"],
    label: "탐지 규칙",
    derive: fromNested("rule.title"),
  },
  { key: ["rule_id"], label: "규칙 ID", format: "mono", derive: fromNested("rule.id") },
  {
    key: ["severity", "rule_level"],
    label: "탐지 심각도",
    format: "detectionSeverity",
    derive: fromNested("rule.level"),
  },
  { key: ["mitre_tags", "mitre_attack"], label: "MITRE ATT&CK", derive: fromNested("rule.mitre_tags") },
  { key: ["rule_description"], label: "규칙 설명", derive: fromNested("rule.description") },
  { key: ["matched_fields"], label: "일치한 필드" },
  { key: ["false_positive_note"], label: "오탐 참고" },
  { key: ["triage_recommendation"], label: "선별 권고" },
  ...EVENT_CORE.filter((def) => def.label !== "규칙(이벤트)"),
  { key: ["rulepack_version"], label: "규칙팩 버전", format: "mono" },
];

const LOGON_SESSION_CORE: FieldDef[] = [
  { key: ["user_name"], label: "사용자" },
  { key: ["target_domain_name"], label: "도메인" },
  { key: ["logon_id"], label: "로그온 ID", format: "mono" },
  { key: ["logon_type"], label: "로그온 유형", format: "logonType" },
  { key: ["source_ip"], label: "출발지 IP", format: "mono" },
  { key: ["workstation_name"], label: "워크스테이션" },
  { key: ["computer"], label: "컴퓨터" },
  t("started_at", "로그온 시각", "logon-start"),
  t("ended_at", "로그오프 시각", "logon-end"),
  { key: ["duration_seconds"], label: "세션 길이(초)", format: "number" },
  { key: ["session_status"], label: "세션 상태" },
  { key: ["event_ids"], label: "관련 이벤트 ID" },
  { key: ["event_count"], label: "이벤트 수", format: "number" },
  { key: ["events"], label: "이벤트(최대 100)" },
  { key: ["session_key"], label: "세션 키", format: "mono" },
];

const RECORD_CANDIDATE_CORE: FieldDef[] = [
  { key: ["record_id"], label: "레코드 ID", format: "mono" },
  t(["timestamp"], "시각(헤더)", "event"),
  { key: ["evtx_record_state"], label: "레코드 상태" },
  { key: ["evtx_record_id_position"], label: "레코드 번호 위치" },
  { key: ["duplicate_of_live_record"], label: "할당 레코드의 중복" },
  { key: ["evtx_record_integrity"], label: "무결성" },
  { key: ["evtx_declared_size", "evtx_available_size"], label: "선언 크기", format: "bytes" },
  { key: ["timestamp_status"], label: "시각 상태" },
  { key: ["extracted_strings"], label: "추출 문자열" },
  { key: ["native_indicators"], label: "지표" },
];

const PREFETCH_CORE: FieldDef[] = [
  { key: ["executable_hint", "header_executable_name", "filename_executable_hint"], label: "실행 파일" },
  { key: ["run_count"], label: "실행 횟수", format: "number" },
  t(["last_run_at", "timestamp"], "최근 실행", "run"),
  { key: ["last_run_times"], label: "실행 시각 목록(최대 8)" },
  { key: ["prefetch_hash", "header_prefetch_hash"], label: "프리페치 해시", format: "mono" },
  { key: ["prefetch_version"], label: "버전" },
  { key: ["volumes", "volume_candidates"], label: "볼륨" },
  { key: ["volume_count"], label: "볼륨 수", format: "number" },
  { key: ["referenced_paths"], label: "참조 파일" },
  { key: ["referenced_path_count"], label: "참조 파일 수", format: "number" },
  { key: ["file_reference_candidates"], label: "파일 참조(MFT)" },
  { key: ["declared_file_size"], label: "선언 크기", format: "bytes" },
  { key: ["prefetch_compression"], label: "압축" },
  { key: ["header_executable_name_may_be_truncated"], label: "실행 파일 이름 잘림 가능" },
];

const PREFETCH_REF_CORE: FieldDef[] = [
  { key: ["referenced_path"], label: "참조 경로", format: "path" },
  { key: ["referenced_file_name"], label: "참조 파일 이름" },
  { key: ["executable_hint", "prefetch_entry_name"], label: "실행 파일" },
  { key: ["volume_device_path"], label: "볼륨 장치 경로", format: "mono" },
  { key: ["load_order_index"], label: "로드 순서", format: "number" },
  { key: ["run_count"], label: "실행 횟수", format: "number" },
  t(["last_run_at", "timestamp"], "최근 실행", "run"),
];

const LNK_CORE: FieldDef[] = [
  { key: ["target_path", "local_base_path", "entry_hint"], label: "대상 경로", format: "path" },
  { key: ["command_line_arguments", "arguments"], label: "인수", format: "mono" },
  { key: ["working_dir", "working_directory"], label: "작업 폴더", format: "path" },
  { key: ["relative_path"], label: "상대 경로", format: "path" },
  { key: ["description"], label: "설명" },
  t("target_created_at", "대상 생성", "target-created"),
  t("target_modified_at", "대상 수정", "target-modified"),
  t("target_accessed_at", "대상 접근", "target-accessed"),
  { key: ["target_file_size"], label: "대상 크기", format: "bytes" },
  { key: ["volume_label"], label: "볼륨 레이블" },
  {
    key: ["volume_serial_number"],
    label: "볼륨 시리얼",
    format: "mono",
    derive: fromNested("link_info.volume_serial_number"),
  },
  { key: ["drive_type_name", "drive_type"], label: "드라이브 종류" },
  { key: ["net_name", "device_name", "common_path_suffix"], label: "네트워크 공유", format: "path" },
  {
    key: ["tracker_machine_id", "machine_id"],
    label: "머신 ID(NetBIOS)",
    format: "mono",
    derive: fromNested("tracker_data.machine_id"),
  },
  { key: ["hostname"], label: "호스트 이름" },
  {
    key: ["droid_volume_id"],
    label: "Droid 볼륨 ID",
    format: "mono",
    derive: firstOf(fromNested("tracker_data.droid_volume_id"), fromNested("tracker_data.volume_droid")),
  },
  {
    key: ["droid_file_id"],
    label: "Droid 파일 ID",
    format: "mono",
    derive: firstOf(fromNested("tracker_data.droid_file_id"), fromNested("tracker_data.file_droid")),
  },
  {
    key: ["birth_droid_volume_id"],
    label: "최초 Droid 볼륨 ID",
    format: "mono",
    derive: firstOf(
      fromNested("tracker_data.birth_droid_volume_id"),
      fromNested("tracker_data.birth_volume_droid"),
    ),
  },
  {
    key: ["birth_droid_file_id"],
    label: "최초 Droid 파일 ID",
    format: "mono",
    derive: firstOf(
      fromNested("tracker_data.birth_droid_file_id"),
      fromNested("tracker_data.birth_file_droid"),
    ),
  },
  {
    key: ["tracker_droid_file_mac_address", "mac_address"],
    label: "MAC 주소(Droid)",
    format: "mono",
    derive: fromNested("tracker_data.mac_address"),
  },
  { key: ["known_folder_ids"], label: "알려진 폴더" },
  { key: ["environment_target"], label: "환경 변수 대상", format: "path" },
  { key: ["link_flag_names"], label: "링크 플래그" },
  { key: ["file_attribute_names"], label: "대상 속성" },
  { key: ["show_command"], label: "표시 방식" },
  { key: ["hot_key"], label: "단축키" },
  { key: ["icon_location"], label: "아이콘 위치", format: "path" },
  { key: ["entry_name"], label: "바로 가기 파일" },
  { key: ["location"], label: "위치" },
  { key: ["user"], label: "사용자 프로필" },
  { key: ["detected_content_label", "detected_content_kind"], label: "감지된 내용" },
  t(["modified_at"], "바로 가기 수정", "modified"),
];

const JUMPLIST_CORE: FieldDef[] = [
  { key: ["application_id_hash", "app_id"], label: "AppID", format: "mono" },
  { key: ["application_name", "app_name"], label: "앱 이름" },
  { key: ["jumplist_kind"], label: "점프 목록 종류" },
  { key: ["destlist_path", "target_path", "entry_hint"], label: "대상 경로", format: "path" },
  { key: ["destlist_entry_number"], label: "항목 번호", format: "number" },
  t(["destlist_last_modified_at", "timestamp"], "마지막 접근(DestList)", "last-accessed"),
  { key: ["destlist_access_count", "destlist_access_count_float_v1"], label: "접근 횟수", format: "number" },
  { key: ["destlist_pinned", "destlist_pin_status"], label: "고정" },
  { key: ["destlist_hostname", "hostname"], label: "호스트 이름" },
  { key: ["destlist_volume_droid"], label: "Droid 볼륨 ID", format: "mono" },
  { key: ["destlist_file_droid"], label: "Droid 파일 ID", format: "mono" },
  { key: ["destlist_birth_volume_droid"], label: "최초 Droid 볼륨 ID", format: "mono" },
  { key: ["destlist_birth_file_droid"], label: "최초 Droid 파일 ID", format: "mono" },
  { key: ["destlist_file_droid_mac_address"], label: "MAC 주소(Droid)", format: "mono" },
  { key: ["lnk_stream_name"], label: "LNK 스트림", format: "mono" },
  { key: ["working_dir"], label: "작업 폴더", format: "path" },
  { key: ["command_line_arguments"], label: "인수", format: "mono" },
  t("target_created_at", "대상 생성", "target-created"),
  t("target_modified_at", "대상 수정", "target-modified"),
  t("target_accessed_at", "대상 접근", "target-accessed"),
  { key: ["volume_serial_number"], label: "볼륨 시리얼", format: "mono" },
  { key: ["tracker_machine_id"], label: "머신 ID(NetBIOS)", format: "mono" },
  { key: ["destinations"], label: "대상 항목" },
  { key: ["destination_count", "destinations_total"], label: "대상 수", format: "number" },
  { key: ["destlist_entry_candidates"], label: "DestList 항목 후보" },
  { key: ["entry_name"], label: "점프 목록 파일" },
  { key: ["user"], label: "사용자 프로필" },
];

const SHELLBAG_CORE: FieldDef[] = [
  {
    key: ["shell_path", "folder_path", "shellbag_path_candidates", "path_candidates"],
    label: "폴더 경로",
    format: "path",
  },
  { key: ["item_name"], label: "항목 이름" },
  { key: ["item_kind"], label: "셸 항목 종류" },
  { key: ["slot_name", "node_slot"], label: "슬롯", format: "mono" },
  { key: ["mru_position"], label: "MRU 순서", format: "number" },
  { key: ["depth"], label: "깊이", format: "number" },
  t(["key_last_written_at", "last_written_at"], "키 마지막 기록", "last-written"),
  t(["item_created_at"], "생성(셸 항목)", "created"),
  t(["item_modified_at"], "수정(셸 항목)", "modified"),
  t(["item_accessed_at"], "접근(셸 항목)", "accessed"),
  { key: ["volume", "network_location"], label: "볼륨/네트워크" },
  { key: ["key_path", "node_key_path", "key", "source_key_path"], label: "키 경로", format: "path" },
  { key: ["hive_name", "hive_hint"], label: "하이브" },
  { key: ["user_sid"], label: "사용자 SID", format: "sid" },
  { key: ["user_hive_scope", "user"], label: "사용자 하이브" },
  { key: ["shellitem"], label: "셸 항목" },
  { key: ["activity_label"], label: "활동" },
  { key: ["value_names"], label: "값 이름" },
];

const REGISTRY_CORE: FieldDef[] = [
  { key: ["key", "key_path", "source_key_path"], label: "키 경로", format: "path" },
  { key: ["hive_hint", "hive_name", "hive"], label: "하이브" },
  { key: ["name", "value_name", "key_name"], label: "이름" },
  { key: ["value_type"], label: "값 종류" },
  { key: ["activity_value", "value_data", "data"], label: "데이터", format: "mono" },
  t(["key_last_written_at", "last_written_at", "timestamp"], "키 마지막 기록", "last-written"),
  { key: ["label", "activity_label"], label: "활동" },
  { key: ["user_activity_category"], label: "활동 분류" },
  { key: ["mru_position"], label: "MRU 순서", format: "number" },
  { key: ["user_sid"], label: "사용자 SID", format: "sid" },
  { key: ["user_hive_scope"], label: "사용자 하이브" },
  { key: ["value_names"], label: "값 이름" },
  { key: ["value_count"], label: "값 수", format: "number" },
  { key: ["subkey_count"], label: "하위 키 수", format: "number" },
  { key: ["persistence_values"], label: "자동 실행 값" },
  { key: ["usb_device"], label: "USB 장치" },
  { key: ["decoded_values"], label: "해석된 값" },
  { key: ["normalized_activity_rows"], label: "활동 행" },
  { key: ["allocation_status"], label: "할당 상태" },
  { key: ["cell_kind"], label: "셀 종류" },
];

const PERSISTENCE_CORE: FieldDef[] = [
  { key: ["value_name", "entry_name", "name"], label: "항목 이름" },
  { key: ["command", "value_data", "data", "image_path"], label: "명령/대상", format: "mono" },
  { key: ["executable_hint"], label: "실행 파일" },
  { key: ["persistence_category"], label: "자동 실행 위치" },
  { key: ["evidence_note"], label: "참고" },
  { key: ["key_path", "key", "source_key_path"], label: "키 경로", format: "path" },
  { key: ["hive_name", "hive_hint"], label: "하이브" },
  t(["key_last_written_at", "last_written_at", "timestamp"], "키 마지막 기록", "last-written"),
  { key: ["user_sid"], label: "사용자 SID", format: "sid" },
  { key: ["persistence_values"], label: "자동 실행 값" },
  { key: ["user_hive_scope", "user"], label: "사용자" },
];

const USB_CORE: FieldDef[] = [
  {
    key: ["friendly_name", "device_description", "device_name"],
    label: "장치 이름",
    derive: fromNested("usb_device.friendly_name"),
  },
  {
    key: ["serial_number", "serial", "usb_serial_number"],
    label: "시리얼",
    format: "mono",
    derive: fromNested("usb_device.serial_hint"),
  },
  { key: ["serial_is_os_generated"], label: "OS가 만든 시리얼" },
  { key: ["vid"], label: "VID", format: "mono" },
  { key: ["pid"], label: "PID", format: "mono" },
  { key: ["vendor"], label: "제조사" },
  { key: ["product"], label: "제품" },
  { key: ["revision"], label: "리비전" },
  {
    key: ["device_type", "device_class_id"],
    label: "장치 종류",
    derive: fromNested("usb_device.device_class"),
  },
  { key: ["drive_letters", "drive_letter"], label: "드라이브 문자" },
  { key: ["volume_guids", "volume_guid"], label: "볼륨 GUID", format: "mono" },
  { key: ["container_id"], label: "컨테이너 ID", format: "mono" },
  t(["first_install_at"], "최초 설치", "first-install"),
  t(["install_at"], "설치", "installed"),
  t(["last_arrival_at"], "마지막 연결", "last-connected"),
  t(["last_removal_at"], "마지막 분리", "last-removal"),
  t(["usb_key_last_written_at", "key_last_written_at", "last_written_at"], "키 마지막 기록", "last-written"),
  { key: ["usb_instance_id"], label: "인스턴스 ID", format: "mono" },
  { key: ["usb_key_path", "key", "key_path", "source_key_path"], label: "키 경로", format: "path" },
  { key: ["control_set"], label: "ControlSet" },
  { key: ["driver"], label: "드라이버" },
];

const MOUNTED_CORE: FieldDef[] = [
  { key: ["mount_name", "value_name", "name"], label: "마운트 지점" },
  { key: ["drive_letter"], label: "드라이브 문자" },
  { key: ["volume_guid"], label: "볼륨 GUID", format: "mono" },
  { key: ["mount_kind", "data_kind"], label: "데이터 종류" },
  { key: ["device_path", "device_id"], label: "장치 경로", format: "mono" },
  { key: ["disk_signature"], label: "디스크 서명", format: "mono" },
  { key: ["partition_offset"], label: "파티션 오프셋", format: "hex" },
  { key: ["partition_guid"], label: "파티션 GUID", format: "mono" },
  { key: ["usb_serial_number"], label: "USB 시리얼", format: "mono" },
  { key: ["usb_vendor", "usb_product"], label: "USB 장치" },
  { key: ["removable_usb"], label: "이동식 USB" },
  { key: ["friendly_name"], label: "장치 이름" },
  { key: ["data_hex"], label: "데이터(헥스, 앞 64바이트)", format: "mono" },
  t(["key_last_written_at", "last_written_at"], "키 마지막 기록", "last-written"),
  { key: ["key_path", "key", "source_key_path"], label: "키 경로", format: "path" },
];

const SERVICE_CORE: FieldDef[] = [
  { key: ["service_name", "name", "key_name"], label: "서비스 이름" },
  { key: ["display_name"], label: "표시 이름" },
  { key: ["image_path", "image_path_hint"], label: "실행 경로", format: "mono" },
  { key: ["service_dll"], label: "서비스 DLL", format: "path" },
  { key: ["start_label", "start_type_label", "start", "start_type"], label: "시작 유형" },
  { key: ["service_type_label", "service_type"], label: "서비스 종류" },
  { key: ["object_name"], label: "실행 계정" },
  { key: ["autostart"], label: "자동 시작" },
  { key: ["group"], label: "그룹" },
  { key: ["description"], label: "설명" },
  t(["key_last_written_at", "last_written_at"], "키 마지막 기록", "last-written"),
  { key: ["control_set"], label: "ControlSet" },
  { key: ["key_path", "key", "source_key_path"], label: "키 경로", format: "path" },
];

const TIMEZONE_CORE: FieldDef[] = [
  { key: ["time_zone_key_name", "standard_name"], label: "표준 시간대" },
  { key: ["time_zone_label_ko"], label: "시간대(한글)" },
  { key: ["utc_offset"], label: "UTC 편차" },
  { key: ["bias_minutes"], label: "편차(분, Bias)", format: "number" },
  { key: ["active_time_bias_minutes"], label: "현재 편차(분)", format: "number" },
  { key: ["daylight_name"], label: "일광 절약 이름" },
  { key: ["daylight_bias_minutes"], label: "일광 절약 편차(분)", format: "number" },
  { key: ["dynamic_daylight_time_disabled"], label: "자동 일광 절약 해제" },
  { key: ["bias_semantics"], label: "편차 의미" },
  t(["key_last_written_at", "last_written_at"], "키 마지막 기록", "last-written"),
  { key: ["key_path", "key", "source_key_path"], label: "키 경로", format: "path" },
];

const SYSTEM_INFO_CORE: FieldDef[] = [
  { key: ["computer_name", "active_computer_name", "tcpip_hostname"], label: "컴퓨터 이름" },
  { key: ["tcpip_domain", "domain"], label: "도메인" },
  { key: ["product_name", "display_version", "edition_id"], label: "제품" },
  { key: ["current_build", "ubr"], label: "빌드" },
  { key: ["registered_owner"], label: "등록 사용자" },
  { key: ["registered_organization"], label: "등록 조직" },
  t(["install_time", "install_date"], "설치", "installed"),
  { key: ["current_control_set", "select_values"], label: "ControlSet" },
  t(["last_shutdown_at"], "마지막 종료", "event"),
  { key: ["connection_name", "interface_guid"], label: "네트워크 연결" },
  { key: ["ip_address", "subnet_mask", "default_gateway"], label: "IP 주소", format: "mono" },
  { key: ["dhcp_enabled"], label: "DHCP" },
  { key: ["name_server"], label: "DNS 서버", format: "mono" },
  t(["lease_obtained_at"], "DHCP 임대", "event"),
  t(["lease_terminates_at"], "DHCP 만료", "expires"),
  { key: ["sid"], label: "SID", format: "sid" },
  { key: ["profile_image_path"], label: "프로필 경로", format: "path" },
  { key: ["display_name", "program_key"], label: "프로그램" },
  { key: ["publisher"], label: "게시자" },
  { key: ["install_location", "uninstall_string"], label: "설치 위치", format: "path" },
  t(["key_last_written_at", "last_written_at"], "키 마지막 기록", "last-written"),
  { key: ["key_path", "key", "source_key_path"], label: "키 경로", format: "path" },
];

const SAM_ACCOUNT_CORE: FieldDef[] = [
  { key: ["user_name", "user_name_candidate", "account_name"], label: "계정" },
  { key: ["well_known_account_ko"], label: "기본 계정" },
  { key: ["full_name"], label: "전체 이름" },
  { key: ["rid", "rid_decimal"], label: "RID", format: "number" },
  { key: ["rid_hex"], label: "RID(16진)", format: "mono" },
  { key: ["sid", "user_sid"], label: "SID", format: "sid" },
  t(["last_logon_at"], "마지막 로그온", "last-logon"),
  t(["password_last_set_at"], "암호 마지막 변경", "password-last-set"),
  t(["last_failed_logon_at"], "마지막 로그온 실패", "last-failed-logon"),
  t(["account_expires_at"], "계정 만료", "account-expires"),
  { key: ["logon_count"], label: "로그온 수", format: "number" },
  { key: ["failed_logon_count"], label: "로그온 실패 수", format: "number" },
  {
    key: ["acb_flags_labels_ko", "acb_flags_names", "acb_flags_hex", "acb_flags", "uac_flags"],
    label: "계정 플래그(UAC)",
  },
  { key: ["account_disabled"], label: "사용 안 함" },
  { key: ["account_locked"], label: "잠김" },
  { key: ["password_never_expires"], label: "암호 만료 없음" },
  { key: ["password_not_required"], label: "암호 필요 없음" },
  { key: ["group_memberships"], label: "그룹" },
  { key: ["admin_member"], label: "관리자 그룹 구성원" },
  { key: ["candidate_role", "account_type_hint"], label: "역할" },
  { key: ["comment", "user_comment"], label: "설명" },
  { key: ["profile_path", "home_directory"], label: "프로필 경로", format: "path" },
  { key: ["logon_script"], label: "로그온 스크립트", format: "path" },
  { key: ["lm_hash_present", "nt_hash_present"], label: "해시 저장됨(LM/NT)" },
  t(
    ["rid_key_last_written_at", "names_key_last_written_at", "key_last_written_at", "last_written_at"],
    "키 마지막 기록",
    "last-written",
  ),
  { key: ["key_path", "key"], label: "키 경로", format: "path" },
];

const SAM_GROUP_CORE: FieldDef[] = [
  { key: ["group_name", "group_name_candidate", "name"], label: "그룹" },
  { key: ["rid", "alias_rid_decimal", "rid_decimal"], label: "RID", format: "number" },
  { key: ["group_sid", "sid"], label: "SID", format: "sid" },
  { key: ["member_names", "member_sids", "member_rids", "members"], label: "구성원" },
  { key: ["member_count"], label: "구성원 수", format: "number" },
  { key: ["privileged_group"], label: "특권 그룹" },
  { key: ["group_scope_ko", "group_scope"], label: "범위" },
  { key: ["comment", "description"], label: "설명" },
  t(["key_last_written_at", "last_written_at"], "키 마지막 기록", "last-written"),
  { key: ["key_path", "key"], label: "키 경로", format: "path" },
];

const EXECUTION_CORE: FieldDef[] = [
  {
    key: ["executable_path", "decoded_name", "display_path", "driver_path", "shortcut_path", "path"],
    label: "실행 파일 경로",
    format: "path",
  },
  { key: ["device_path"], label: "장치 경로", format: "mono" },
  {
    key: ["program_name", "driver_name", "device_model", "original_file_name", "name"],
    label: "프로그램",
  },
  { key: ["product_name"], label: "제품" },
  { key: ["publisher", "driver_company", "manufacturer"], label: "게시자" },
  { key: ["version", "driver_version", "product_version"], label: "버전" },
  { key: ["sha1", "file_id"], label: "SHA-1(파일)", format: "mono" },
  { key: ["binary_type"], label: "바이너리 유형" },
  { key: ["size_bytes", "size"], label: "파일 크기", format: "bytes" },
  { key: ["run_counter", "run_count"], label: "실행 횟수", format: "number" },
  { key: ["focus_count"], label: "포커스 횟수", format: "number" },
  { key: ["total_focus_time_ms"], label: "포커스 시간(ms)", format: "number" },
  { key: ["cache_order"], label: "캐시 순서", format: "number" },
  { key: ["exec_flag"], label: "실행 플래그" },
  { key: ["sequence_number"], label: "시퀀스", format: "number" },
  { key: ["user_sid", "sid"], label: "사용자 SID", format: "sid" },
  { key: ["user_name", "user"], label: "사용자" },
  t(["timestamp"], "기록 시각", "event"),
  t(["link_date"], "링크 시각", "created"),
  t(["install_date", "first_install_date"], "설치", "installed"),
  t(["key_last_written_at", "last_written_at"], "키 마지막 기록", "last-written"),
  { key: ["section", "label"], label: "섹션" },
  { key: ["key_name", "guid"], label: "키 이름", format: "mono" },
  { key: ["key_path", "key", "source_key", "source_key_path"], label: "키 경로", format: "path" },
  { key: ["control_set"], label: "ControlSet" },
  { key: ["shortcut_target_path"], label: "바로 가기 대상", format: "path" },
  { key: ["device_instance_id", "container_id"], label: "장치 ID", format: "mono" },
];

const BROWSER_VISIT_CORE: FieldDef[] = [
  t(["timestamp", "visit_time"], "방문 시각", "visited"),
  { key: ["url"], label: "URL", format: "url" },
  { key: ["title"], label: "제목" },
  { key: ["visit_count"], label: "방문 수", format: "number" },
  { key: ["typed_count"], label: "직접 입력 수", format: "number" },
  { key: ["transition_core", "transition"], label: "전환" },
  { key: ["transition_qualifiers"], label: "전환 한정자" },
  { key: ["from_url"], label: "이전 URL", format: "url" },
  { key: ["external_referrer_url"], label: "외부 참조 URL", format: "url" },
  { key: ["visit_duration_seconds", "visit_duration_micros"], label: "머문 시간" },
  { key: ["visit_time_raw"], label: "방문 시각(원문 WebKit)", format: "mono" },
  { key: ["domain"], label: "도메인" },
  { key: ["browser"], label: "브라우저" },
  { key: ["profile"], label: "프로필" },
  { key: ["user"], label: "사용자" },
];

const BROWSER_DOWNLOAD_CORE: FieldDef[] = [
  t(["started_at", "timestamp"], "다운로드 시작", "download-start"),
  t(["ended_at"], "다운로드 완료", "download-end"),
  { key: ["source_url", "url"], label: "URL", format: "url" },
  { key: ["tab_url"], label: "탭 URL", format: "url" },
  { key: ["referrer", "tab_referrer_url", "site_url"], label: "참조 URL", format: "url" },
  { key: ["target_path", "current_path"], label: "대상 경로", format: "path" },
  { key: ["total_bytes", "received_bytes"], label: "크기", format: "bytes" },
  { key: ["state_name", "state"], label: "상태" },
  { key: ["danger_type_name", "danger_type"], label: "위험 판정" },
  { key: ["interrupt_reason"], label: "중단 사유" },
  { key: ["opened"], label: "열림" },
  { key: ["mime_type", "original_mime_type"], label: "MIME" },
  { key: ["url_chain"], label: "URL 체인" },
  t(["last_accessed_at"], "마지막 열람", "last-accessed"),
  { key: ["by_extension_name", "by_extension_id"], label: "확장 프로그램" },
  { key: ["guid"], label: "GUID", format: "mono" },
  { key: ["browser"], label: "브라우저" },
  { key: ["profile"], label: "프로필" },
  { key: ["user"], label: "사용자" },
];

const BROWSER_HISTORY_CORE: FieldDef[] = [
  t(["timestamp"], "마지막 방문", "last-visited"),
  { key: ["url"], label: "URL", format: "url" },
  { key: ["title"], label: "제목" },
  { key: ["visit_count"], label: "방문 수", format: "number" },
  { key: ["typed_count"], label: "직접 입력 수", format: "number" },
  { key: ["hidden"], label: "숨김" },
  { key: ["last_visit_time_raw"], label: "마지막 방문(원문 WebKit)", format: "mono" },
  { key: ["domain"], label: "도메인" },
  { key: ["browser"], label: "브라우저" },
  { key: ["profile"], label: "프로필" },
  { key: ["user"], label: "사용자" },
  { key: ["history_count"], label: "방문 기록 수", format: "number" },
  { key: ["download_count"], label: "다운로드 수", format: "number" },
  { key: ["top_domains"], label: "상위 도메인" },
];

const BROWSER_COOKIE_CORE: FieldDef[] = [
  { key: ["host", "host_key"], label: "호스트" },
  { key: ["name"], label: "쿠키 이름" },
  { key: ["path"], label: "경로" },
  t(["created_at", "timestamp"], "생성", "created"),
  t(["last_accessed_at"], "마지막 접근", "last-accessed"),
  t(["last_updated_at"], "마지막 갱신", "last-updated"),
  t(["expires_at"], "만료", "expires"),
  { key: ["session_cookie"], label: "세션 쿠키" },
  { key: ["is_persistent"], label: "영구 쿠키" },
  { key: ["is_secure"], label: "Secure" },
  { key: ["is_httponly"], label: "HttpOnly" },
  { key: ["samesite"], label: "SameSite" },
  { key: ["value_present"], label: "값 있음" },
  { key: ["value_encrypted"], label: "값 암호화" },
  { key: ["top_frame_site_key"], label: "최상위 사이트" },
  { key: ["browser"], label: "브라우저" },
  { key: ["profile"], label: "프로필" },
];

const BROWSER_LOGIN_CORE: FieldDef[] = [
  { key: ["origin", "action_url", "signon_realm"], label: "사이트", format: "url" },
  { key: ["username", "display_name"], label: "사용자 이름" },
  t(["date_created", "timestamp"], "저장", "created"),
  t(["date_last_used"], "마지막 사용", "last-used"),
  t(["date_password_modified"], "암호 변경", "modified"),
  t(["date_synced"], "동기화", "last-updated"),
  { key: ["times_used"], label: "사용 횟수", format: "number" },
  { key: ["password_stored"], label: "암호 저장됨" },
  { key: ["blacklisted_by_user"], label: "저장 안 함(사용자)" },
  { key: ["federation_url"], label: "연동 URL", format: "url" },
  { key: ["browser"], label: "브라우저" },
  { key: ["profile"], label: "프로필" },
];

const BROWSER_SEARCH_CORE: FieldDef[] = [
  t(["timestamp"], "검색 시각", "visited"),
  { key: ["term", "normalized_term"], label: "검색어" },
  { key: ["url"], label: "URL", format: "url" },
  { key: ["title"], label: "제목" },
  { key: ["search_engine_host"], label: "검색 엔진" },
  { key: ["browser"], label: "브라우저" },
  { key: ["profile"], label: "프로필" },
];

const BROWSER_BOOKMARK_CORE: FieldDef[] = [
  { key: ["name", "title"], label: "제목" },
  { key: ["url"], label: "URL", format: "url" },
  { key: ["folder"], label: "폴더" },
  t(["date_added", "timestamp"], "추가", "created"),
  t(["date_last_used"], "마지막 사용", "last-used"),
  { key: ["browser"], label: "브라우저" },
  { key: ["profile"], label: "프로필" },
];

const BROWSER_EXTENSION_CORE: FieldDef[] = [
  { key: ["name"], label: "확장 이름" },
  { key: ["extension_id"], label: "확장 ID", format: "mono" },
  { key: ["version"], label: "버전" },
  { key: ["description"], label: "설명" },
  { key: ["permissions", "active_api_permissions"], label: "권한" },
  { key: ["state", "disable_reasons"], label: "상태" },
  t(["install_time", "timestamp"], "설치", "installed"),
  t(["last_update_time"], "마지막 갱신", "last-updated"),
  { key: ["from_webstore"], label: "웹 스토어 설치" },
  { key: ["location_name", "location"], label: "설치 출처" },
  { key: ["was_installed_by_default"], label: "기본 설치" },
  { key: ["manifest_path"], label: "매니페스트 경로", format: "path" },
  { key: ["browser"], label: "브라우저" },
  { key: ["profile"], label: "프로필" },
];

const BROWSER_AUTOFILL_CORE: FieldDef[] = [
  { key: ["field_name", "field_id", "name"], label: "입력란" },
  { key: ["domain"], label: "도메인" },
  { key: ["value_preview"], label: "값(마스킹)" },
  { key: ["mask_reason"], label: "마스킹 사유" },
  { key: ["value_length"], label: "값 길이", format: "number" },
  { key: ["value_sha256"], label: "값 SHA-256", format: "mono" },
  { key: ["use_count"], label: "사용 횟수", format: "number" },
  t(["date_created", "timestamp"], "생성", "created"),
  t(["date_last_used"], "마지막 사용", "last-used"),
  { key: ["browser"], label: "브라우저" },
  { key: ["profile"], label: "프로필" },
];

const DOCUMENT_CORE: FieldDef[] = [
  { key: ["locked_document_name_hint", "file_name", "entry_name"], label: "문서" },
  { key: ["document_family", "container_format", "lock_format"], label: "문서 형식" },
  { key: ["title"], label: "제목" },
  { key: ["subject"], label: "주제" },
  { key: ["author", "author_candidates"], label: "작성자" },
  { key: ["last_modified_by"], label: "마지막 수정자" },
  { key: ["lock_owner", "lock_owner_ansi"], label: "잠금 소유자" },
  { key: ["lock_owner_host"], label: "잠금 호스트" },
  { key: ["company"], label: "회사" },
  { key: ["manager"], label: "관리자" },
  { key: ["application", "application_version"], label: "작성 프로그램" },
  { key: ["template"], label: "서식 파일" },
  t(["created_at"], "문서 생성(내부)", "created"),
  t(["modified_at"], "문서 수정(내부)", "modified"),
  t(["last_printed_at"], "마지막 인쇄", "event"),
  { key: ["timestamps_without_zone"], label: "시간대 없는 시각" },
  { key: ["revision"], label: "수정 번호" },
  { key: ["total_edit_time", "total_edit_time_seconds"], label: "총 편집 시간" },
  { key: ["page_count"], label: "쪽 수", format: "number" },
  { key: ["word_count"], label: "단어 수", format: "number" },
  { key: ["keywords", "comments", "category"], label: "키워드/메모" },
  { key: ["encrypted", "encryption_reason"], label: "암호화" },
  { key: ["macro_profile"], label: "매크로" },
  { key: ["external_reference_candidates"], label: "외부 참조" },
  { key: ["risk_flags"], label: "위험 표시" },
];

const FILE_CORE: FieldDef[] = [
  { key: ["name", "file_name"], label: "파일 이름" },
  { key: ["path", "relative_path", "full_path"], label: "경로", format: "path" },
  { key: ["extension"], label: "확장자" },
  { key: ["size", "size_bytes"], label: "크기", format: "bytes" },
  { key: ["category", "categories"], label: "분류" },
  t(["fs_created_at"], "생성(파일 시스템)", "created"),
  t(["fs_modified_at"], "수정(파일 시스템)", "modified"),
  t(["fs_accessed_at"], "접근(파일 시스템)", "accessed"),
  t(["fs_changed_at"], "MFT 변경", "mft-modified"),
  t(["modified_at"], "수정(원천 표시 참고)", "modified"),
  { key: ["modified_at_origin", "time_origin"], label: "시각 출처" },
  { key: ["is_deleted", "deletionState"], label: "삭제 여부" },
  { key: ["entry_number", "mft_entry"], label: "MFT 엔트리", format: "number" },
  { key: ["mime_type"], label: "MIME" },
  { key: ["attributes"], label: "속성" },
  { key: ["signature", "file_signature", "detected_signature_kind"], label: "시그니처" },
];

const MFT_CORE: FieldDef[] = [
  { key: ["file_path", "path_candidates"], label: "경로", format: "path" },
  { key: ["record_number"], label: "레코드(엔트리) 번호", format: "number" },
  { key: ["sequence_number"], label: "시퀀스", format: "number" },
  { key: ["parent_reference_decoded", "parent_reference"], label: "부모 참조", format: "mono" },
  { key: ["in_use"], label: "사용 중" },
  { key: ["deleted_hint"], label: "삭제 추정" },
  { key: ["rename_hint"], label: "이름 변경 추정" },
  { key: ["directory"], label: "디렉터리" },
  { key: ["used_size", "allocated_size"], label: "크기", format: "bytes" },
  { key: ["usn"], label: "USN", format: "number" },
  { key: ["reason_flags", "reason", "reason_raw"], label: "USN 사유" },
  { key: ["file_attributes_names", "file_attributes"], label: "파일 속성" },
  { key: ["time_stomping_suspected"], label: "타임스톰핑 의심" },
  { key: ["standard_information"], label: "$STANDARD_INFORMATION" },
  { key: ["file_name_entries"], label: "$FILE_NAME" },
  t(["timestamp"], "시각", "event"),
];

const TIMELINE_CORE: FieldDef[] = [
  t(["timestamp"], "시각", "event"),
  { key: ["timeKinds", "tsLabels", "tsKind"], label: "시각 종류" },
  { key: ["eventType"], label: "이벤트", format: "mono" },
  { key: ["sourceArtifactType"], label: "원본 아티팩트 유형", format: "mono" },
  { key: ["source"], label: "출처" },
  { key: ["tsZone"], label: "시간대" },
];

const INDICATOR_CORE: FieldDef[] = [
  { key: ["value", "indicator"], label: "지표 값", format: "mono" },
  { key: ["type", "indicator_type"], label: "지표 유형" },
  { key: ["severity"], label: "심각도", format: "detectionSeverity" },
  { key: ["rule", "rule_name", "matched_rule"], label: "규칙" },
  { key: ["count", "occurrences"], label: "출현 수", format: "number" },
  { key: ["sources", "source"], label: "출처" },
  t(["first_seen", "timestamp"], "처음 발견", "event"),
];

const TASK_CORE: FieldDef[] = [
  { key: ["task_uri"], label: "작업 경로", format: "path" },
  { key: ["command", "executable_name"], label: "명령", format: "mono" },
  { key: ["arguments"], label: "인수", format: "mono" },
  { key: ["command_line", "action_preview"], label: "명령줄", format: "mono" },
  { key: ["working_directory"], label: "작업 폴더", format: "path" },
  { key: ["author"], label: "작성자" },
  { key: ["user_id"], label: "실행 계정(UserId)" },
  { key: ["logon_type"], label: "로그온 방식" },
  { key: ["run_level"], label: "실행 수준" },
  { key: ["trigger_types"], label: "트리거" },
  { key: ["trigger_details"], label: "트리거 세부" },
  { key: ["start_boundaries"], label: "시작 시각(트리거)" },
  { key: ["actions"], label: "동작" },
  { key: ["principals"], label: "주체" },
  { key: ["hidden"], label: "숨김" },
  { key: ["normalized_action"], label: "동작 분류" },
  t(["registration_date"], "등록", "registered", fromNested("task_temporal_profile.registration_date")),
  t(["modified_at"], "작업 파일 수정", "modified"),
];

const WER_CORE: FieldDef[] = [
  { key: ["application_name", "application", "signature_application_name"], label: "앱" },
  { key: ["application_path"], label: "앱 경로", format: "path" },
  { key: ["application_version"], label: "앱 버전" },
  { key: ["event_type_name", "friendly_event_name", "event_type"], label: "이벤트 유형" },
  { key: ["exception_code"], label: "예외 코드", format: "mono" },
  { key: ["exception_offset"], label: "예외 오프셋", format: "mono" },
  { key: ["fault_module_name", "module"], label: "오류 모듈" },
  { key: ["fault_module_path"], label: "오류 모듈 경로", format: "path" },
  { key: ["fault_module_version"], label: "오류 모듈 버전" },
  t(["event_time", "timestamp"], "이벤트 시각", "event"),
  { key: ["event_time_raw"], label: "이벤트 시각(원문)", format: "mono" },
  t(["upload_time"], "업로드", "upload"),
  { key: ["report_id"], label: "보고서 ID", format: "mono" },
  { key: ["bucket_id", "bucket"], label: "버킷", format: "mono" },
  { key: ["cab_id"], label: "CAB ID", format: "mono" },
  { key: ["package_full_name"], label: "패키지" },
  { key: ["problem_signature"], label: "문제 서명" },
  { key: ["report_store"], label: "보고서 저장소" },
];

const DEFENDER_CORE: FieldDef[] = [
  t(["timestamp"], "시각", "event"),
  { key: ["interesting_entries"], label: "주요 항목" },
  { key: ["entry_count"], label: "항목 수", format: "number" },
  { key: ["interesting_entry_count"], label: "주요 항목 수", format: "number" },
  { key: ["policy_entries"], label: "정책 항목" },
  { key: ["exclusion_entries"], label: "예외(제외) 항목" },
  { key: ["disabled_protection_entries"], label: "꺼진 보호 기능" },
  { key: ["tamper_entries"], label: "변조 방지" },
  t(["modified_at"], "로그 파일 수정", "modified"),
];

const ZONE_CORE: FieldDef[] = [
  { key: ["target_name", "host_file_name"], label: "대상 파일" },
  {
    key: ["host_file_path", "host_file_path_candidate", "host_relative_path"],
    label: "대상 경로",
    format: "path",
  },
  { key: ["zone_id", "app_zone_id"], label: "Zone ID(영역)" },
  { key: ["zone_name"], label: "영역 이름" },
  { key: ["host_url"], label: "다운로드 URL(HostUrl)", format: "url" },
  { key: ["referrer_url"], label: "참조 URL(ReferrerUrl)", format: "url" },
  { key: ["last_writer_package_family_name"], label: "기록한 앱" },
  { key: ["stream_name"], label: "스트림 이름", format: "mono" },
  { key: ["stream_type", "stream_family"], label: "스트림 종류" },
  { key: ["detected_signature_kind"], label: "감지 서명" },
  { key: ["zone_identifier_fields", "fields"], label: "Zone.Identifier 내용" },
  { key: ["host_timestamps"], label: "대상 파일 시각" },
  t(["modified_at"], "스트림 수정", "modified"),
];

const SYSTEM_LOG_CORE: FieldDef[] = [
  t(["timestamp"], "시각", "event"),
  { key: ["entry_count", "parsed_row_count", "line_count_sampled"], label: "항목 수", format: "number" },
  { key: ["suspicious_line_count", "blocked_count"], label: "의심/차단 수", format: "number" },
  { key: ["sample_entries", "suspicious_line_samples", "parsed_log"], label: "표본 항목" },
  { key: ["request_file_correlation"], label: "요청-파일 상관" },
  t(["modified_at"], "로그 파일 수정", "modified"),
];

const CRASH_DUMP_CORE: FieldDef[] = [
  { key: ["memory_file_kind"], label: "덤프 종류" },
  { key: ["process_name", "process_image_path"], label: "프로세스", format: "path" },
  { key: ["pid"], label: "PID", format: "mono" },
  t(["dump_time", "timestamp"], "덤프 기록", "event"),
  t(["process_create_time"], "프로세스 생성", "created"),
  { key: ["exception_code", "exception_name"], label: "예외", format: "mono" },
  { key: ["exception_address"], label: "예외 주소", format: "mono" },
  { key: ["exception_thread_id"], label: "예외 스레드", format: "mono" },
  { key: ["os_version"], label: "OS 버전" },
  { key: ["processor_architecture"], label: "아키텍처" },
  { key: ["module_count"], label: "모듈 수", format: "number" },
  { key: ["indicator_pivots"], label: "지표 후보" },
  { key: ["environment_variables"], label: "환경 변수" },
  { key: ["minidump"], label: "미니덤프 구조" },
];

const KAKAO_CORE: FieldDef[] = [
  { key: ["display_label", "candidate_kind"], label: "후보 종류" },
  { key: ["candidate_value"], label: "후보 값", format: "mono" },
  { key: ["candidate_value_sha256"], label: "후보 값 SHA-256", format: "mono" },
  { key: ["evidence_nature"], label: "증거 성격" },
  { key: ["field_names"], label: "필드" },
  { key: ["values_redacted"], label: "값 가림" },
  { key: ["registry_key_path"], label: "레지스트리 키", format: "path" },
  { key: ["registry_value_name"], label: "레지스트리 값", format: "mono" },
  t(["registry_key_last_written"], "키 마지막 기록", "last-written"),
  { key: ["decoded_strings"], label: "해석된 문자열" },
  { key: ["matched_terms"], label: "일치한 용어" },
  { key: ["path_candidates", "url_candidates"], label: "경로·URL 후보" },
  { key: ["source_offset"], label: "원본 오프셋", format: "hex" },
  { key: ["risk_score"], label: "위험 점수", format: "number" },
];

const STRING_CANDIDATE_CORE: FieldDef[] = [
  {
    key: ["executable_path", "candidate_value", "decoded_string", "string_value", "value", "path"],
    label: "문자열",
    format: "mono",
  },
  { key: ["evidence_class"], label: "증거 분류" },
  { key: ["source_offset", "string_offset", "offset"], label: "원본 오프셋", format: "hex" },
  { key: ["source_encoding", "encoding"], label: "인코딩" },
  { key: ["sha1_candidates"], label: "SHA-1 후보", format: "mono" },
  { key: ["user_sid"], label: "SID 후보", format: "sid" },
  { key: ["cache_order"], label: "캐시 순서", format: "number" },
  { key: ["timestamp_candidate"], label: "시각 후보" },
  { key: ["nearby_metadata_candidates"], label: "주변 메타데이터 후보" },
  { key: ["string_candidate_total"], label: "후보 수", format: "number" },
];

const SYNTHETIC_MEDIA_CORE: FieldDef[] = [
  { key: ["entry_name", "file_name"], label: "파일" },
  { key: ["score"], label: "선별 점수", format: "number" },
  { key: ["band_label", "band"], label: "점수 구간" },
  { key: ["verdict"], label: "선별 결과" },
  { key: ["score_semantics"], label: "점수 의미" },
  { key: ["score_guidance"], label: "점수 안내" },
  { key: ["signals"], label: "단서" },
  { key: ["signal_count"], label: "단서 수", format: "number" },
  { key: ["limitations"], label: "한계" },
  { key: ["source_guess"], label: "출처 추정" },
  { key: ["next_checks"], label: "다음 확인" },
  { key: ["scan_status", "scan_error"], label: "스캔 상태" },
  { key: ["scan_file_count"], label: "스캔 파일 수", format: "number" },
  { key: ["unscanned_candidate_count"], label: "미선별 후보 수", format: "number" },
  { key: ["scan_cap_note"], label: "상한 안내" },
];

const POWERSHELL_CORE: FieldDef[] = [
  { key: ["command_line", "command"], label: "명령", format: "mono" },
  { key: ["source_index"], label: "줄 순번", format: "number" },
  { key: ["user", "user_name"], label: "사용자" },
  t(["timestamp", "modified_at"], "기록 파일 수정(명령 시각 아님)", "modified"),
];

const RDP_CORE: FieldDef[] = [
  { key: ["destination", "server", "host", "address"], label: "대상 서버", format: "mono" },
  { key: ["username_hint", "user_name", "username"], label: "사용자 이름" },
  { key: ["mru_position", "mru_index"], label: "MRU 순서", format: "number" },
  { key: ["user", "user_hive_scope"], label: "사용자 프로필" },
  t(["key_last_written_at", "last_written_at", "timestamp", "modified_at"], "마지막 기록", "last-written"),
];

const RECYCLE_CORE: FieldDef[] = [
  { key: ["original_path"], label: "원래 경로", format: "path" },
  { key: ["deleted_file_size"], label: "원래 크기", format: "bytes" },
  t(["deleted_at"], "삭제", "event"),
  { key: ["sid_hint", "user_sid"], label: "사용자 SID", format: "sid" },
  { key: ["recycle_id"], label: "휴지통 ID", format: "mono" },
  { key: ["paired_payload_path"], label: "$R 파일", format: "path" },
  { key: ["format_version"], label: "형식 버전" },
];

const SRUM_CORE: FieldDef[] = [
  { key: ["executable_path", "app_id"], label: "앱", format: "path" },
  { key: ["user"], label: "사용자" },
  { key: ["bytes_sent"], label: "보낸 바이트", format: "bytes" },
  { key: ["bytes_received"], label: "받은 바이트", format: "bytes" },
  { key: ["bytes_total"], label: "합계", format: "bytes" },
  { key: ["interface_luid", "network_profile"], label: "네트워크" },
  { key: ["cpu_time"], label: "CPU 시간" },
  { key: ["srum_table_family"], label: "SRUM 테이블" },
  t(["timestamp"], "기록 시각", "event"),
];

const GENERIC_CORE: FieldDef[] = [
  t(["timestamp", "time", "event_time", "normalized_time"], "시각", "event"),
  { key: ["title", "name", "entry_name", "file_name"], label: "이름" },
  {
    key: ["message", "message_text_preview", "message_text", "summary", "description", "detail"],
    label: "내용",
  },
  { key: ["user", "user_name", "account_name"], label: "사용자" },
  { key: ["url"], label: "URL", format: "url" },
  { key: ["target_path", "path"], label: "경로", format: "path" },
  t(["created_at"], "생성", "created"),
  t(["modified_at"], "수정", "modified"),
];

export const FIELD_SHEETS: readonly FieldSheet[] = [
  {
    id: "eventlog-detection",
    label: "이벤트 로그 탐지",
    types: ["eventlog-detection"],
    core: DETECTION_CORE,
    table: { key: EVENT_DATA_KEYS, label: "EventData" },
    recordId: ["record_id", "event_record_id"],
  },
  {
    id: "eventlog-logon-session",
    label: "로그온 세션",
    types: ["eventlog-logon-session"],
    core: LOGON_SESSION_CORE,
    recordId: ["session_key", "logon_id"],
  },
  {
    id: "eventlog-record-candidate",
    label: "EVTX 레코드 후보",
    types: ["eventlog-record-candidate"],
    core: RECORD_CANDIDATE_CORE,
    recordId: ["record_id"],
  },
  {
    id: "eventlog-event",
    label: "이벤트 로그",
    types: ["eventlog-event"],
    kinds: ["eventlog"],
    core: EVENT_CORE,
    table: { key: EVENT_DATA_KEYS, label: "EventData" },
    recordId: ["record_id", "event_record_id"],
  },
  {
    id: "prefetch-file",
    label: "프리페치",
    types: ["prefetch-file", "prefetch-invalid-content"],
    kinds: ["windows-prefetch"],
    core: PREFETCH_CORE,
    recordId: ["prefetch_hash"],
  },
  {
    id: "prefetch-reference",
    label: "프리페치 참조 파일",
    types: ["prefetch-reference"],
    core: PREFETCH_REF_CORE,
  },
  {
    id: "shortcut",
    label: "바로 가기(LNK)",
    types: [
      "recent-shortcut",
      "shell-shortcut",
      "recent-shortcut-invalid-content",
      "shell-shortcut-invalid-content",
    ],
    kinds: ["recent-files"],
    core: LNK_CORE,
  },
  {
    id: "jumplist",
    label: "점프 목록",
    types: ["jumplist-entry", "jumplist-automatic", "jumplist-custom"],
    core: JUMPLIST_CORE,
    recordId: ["destlist_entry_number", "application_id_hash"],
  },
  {
    id: "shellbag",
    label: "셸백",
    prefixes: ["shellbag"],
    kinds: ["windows-shellbags"],
    core: SHELLBAG_CORE,
    recordId: ["key_path", "node_key_path", "key", "source_key_path"],
  },
  {
    id: "usb",
    label: "USB 장치",
    types: ["windows-usb-device", "registry-usb", "usb-setupapi-device-install-candidate"],
    core: USB_CORE,
    recordId: ["serial_number", "usb_key_path", "key", "key_path"],
  },
  {
    id: "mounted-device",
    label: "마운트된 장치",
    types: ["windows-mounted-device"],
    core: MOUNTED_CORE,
    recordId: ["key_path", "key"],
  },
  {
    id: "service",
    label: "서비스",
    types: ["windows-service-config"],
    core: SERVICE_CORE,
    recordId: ["key_path", "key"],
  },
  {
    id: "timezone",
    label: "표준 시간대",
    types: ["windows-timezone"],
    core: TIMEZONE_CORE,
    recordId: ["key_path", "key"],
  },
  {
    id: "system-info",
    label: "시스템 정보",
    types: [
      "windows-control-set",
      "windows-computer-name",
      "windows-network-interface",
      "windows-os-version",
      "windows-profile-list-entry",
      "windows-installed-program",
    ],
    core: SYSTEM_INFO_CORE,
    recordId: ["key_path", "key"],
  },
  {
    id: "persistence",
    label: "자동 실행",
    types: ["registry-persistence-entry", "registry-run-key"],
    core: PERSISTENCE_CORE,
    table: { key: ["values"], label: "값" },
    recordId: ["key_path", "key"],
  },
  {
    id: "sam-account",
    label: "SAM 계정",
    types: ["windows-sam-account", "windows-sam-account-candidate"],
    core: SAM_ACCOUNT_CORE,
    recordId: ["sid", "rid", "rid_decimal"],
  },
  {
    id: "sam-group",
    label: "SAM 그룹",
    types: ["windows-sam-group", "windows-sam-group-candidate", "windows-group-membership"],
    core: SAM_GROUP_CORE,
    recordId: ["group_sid", "sid", "rid"],
  },
  {
    id: "registry",
    label: "레지스트리",
    prefixes: ["registry-"],
    kinds: ["windows-registry"],
    core: REGISTRY_CORE,
    table: { key: ["values"], label: "값" },
    recordId: ["key", "key_path", "source_key_path"],
  },
  {
    id: "execution",
    label: "실행 흔적",
    prefixes: ["amcache-", "shimcache-", "bam-", "userassist-"],
    kinds: ["windows-execution"],
    core: EXECUTION_CORE,
    table: { key: ["values"], label: "값" },
    recordId: ["key_path", "key", "source_key"],
  },
  {
    id: "browser-visit",
    label: "브라우저 방문",
    types: ["browser-visit", "mobile-browser"],
    core: BROWSER_VISIT_CORE,
    recordId: ["source_row_id", "url_id"],
  },
  {
    id: "browser-download",
    label: "브라우저 다운로드",
    types: ["browser-download"],
    core: BROWSER_DOWNLOAD_CORE,
    recordId: ["source_row_id", "guid"],
  },
  {
    id: "browser-history",
    label: "브라우저 방문 기록",
    types: ["browser-history", "browser-history-downloads", "macos-browser-history-downloads"],
    kinds: ["browser"],
    core: BROWSER_HISTORY_CORE,
    recordId: ["source_row_id"],
  },
  {
    id: "browser-cookie",
    label: "쿠키",
    types: ["browser-cookie"],
    core: BROWSER_COOKIE_CORE,
    recordId: ["source_row_id"],
  },
  {
    id: "browser-login",
    label: "저장된 로그인",
    types: ["browser-login"],
    core: BROWSER_LOGIN_CORE,
    recordId: ["source_row_id"],
  },
  {
    id: "browser-search",
    label: "검색어",
    types: ["browser-search"],
    core: BROWSER_SEARCH_CORE,
    recordId: ["source_row_id"],
  },
  {
    id: "browser-bookmark",
    label: "북마크",
    types: ["browser-bookmark"],
    core: BROWSER_BOOKMARK_CORE,
    recordId: ["guid"],
  },
  {
    id: "browser-extension",
    label: "브라우저 확장",
    types: ["browser-extension"],
    core: BROWSER_EXTENSION_CORE,
    recordId: ["extension_id"],
  },
  {
    id: "browser-autofill",
    label: "자동완성",
    types: ["browser-autofill", "browser-autofill-address", "browser-credit-card"],
    core: BROWSER_AUTOFILL_CORE,
  },
  {
    id: "document",
    label: "문서 메타데이터",
    types: ["document-metadata-risk", "document-lock-owner"],
    core: DOCUMENT_CORE,
  },
  { id: "task", label: "예약 작업", types: ["task-scheduler-task"], core: TASK_CORE, recordId: ["task_uri"] },
  { id: "wer", label: "오류 보고(WER)", types: ["wer-report"], core: WER_CORE, recordId: ["report_id"] },
  { id: "defender", label: "Defender", prefixes: ["defender-"], core: DEFENDER_CORE },
  {
    id: "zone",
    label: "Zone.Identifier",
    types: ["zone-identifier", "ads-stream-candidate"],
    core: ZONE_CORE,
  },
  {
    id: "system-log",
    label: "시스템 로그",
    types: ["firewall-log", "web-server-log"],
    core: SYSTEM_LOG_CORE,
  },
  {
    id: "crash-dump",
    label: "크래시 덤프",
    types: ["crash-dump-indicators"],
    prefixes: ["memory-"],
    core: CRASH_DUMP_CORE,
  },
  { id: "kakaotalk", label: "카카오톡 후보", prefixes: ["kakaotalk-windows-"], core: KAKAO_CORE },
  {
    id: "string-candidate",
    label: "문자열 후보",
    suffixes: ["-string-candidate", "-strings"],
    core: STRING_CANDIDATE_CORE,
  },
  { id: "summary", label: "요약(집계)", suffixes: ["-summary", "-scan-summary"], core: GENERIC_CORE },
  {
    id: "synthetic-media",
    label: "합성 미디어 선별",
    prefixes: ["synthetic-media"],
    kinds: ["synthetic-media"],
    core: SYNTHETIC_MEDIA_CORE,
  },
  {
    id: "powershell",
    label: "PowerShell 기록",
    types: ["powershell-history-command"],
    core: POWERSHELL_CORE,
  },
  { id: "rdp", label: "원격 데스크톱", prefixes: ["rdp-"], core: RDP_CORE },
  {
    id: "recycle",
    label: "휴지통",
    types: ["recycle-bin-entry"],
    core: RECYCLE_CORE,
    recordId: ["recycle_id"],
  },
  { id: "srum", label: "SRUM", prefixes: ["srum-"], core: SRUM_CORE },
  {
    id: "mft",
    label: "MFT/USN",
    types: ["mft-record", "mft-file", "usn-record"],
    core: MFT_CORE,
    recordId: ["record_number", "usn"],
  },
];

/** Sheets of non-artifact collections (files · timeline · indicators). */
const COLLECTION_SHEETS: Record<string, FieldSheet> = {
  files: { id: "file", label: "파일", core: FILE_CORE },
  timeline: { id: "timeline", label: "타임라인 이벤트", core: TIMELINE_CORE },
  indicators: { id: "indicator", label: "지표", core: INDICATOR_CORE },
};

const GENERIC_SHEET: FieldSheet = { id: "generic", label: "레코드", core: GENERIC_CORE };

/** The sheet of an artifact type (exact type, then prefix/suffix, then the grid kind); null = generic. */
export function sheetForType(type: string | null | undefined, kind?: string): FieldSheet | null {
  const ty = type ?? "";
  if (ty) {
    // "-string-candidate" first: the string scans of amcache/bam/shimcache are not their families.
    const suffixed = FIELD_SHEETS.find((sheet) => sheet.suffixes?.some((s) => ty.endsWith(s)));
    if (suffixed) return suffixed;
    const exact = FIELD_SHEETS.find((sheet) => sheet.types?.includes(ty));
    if (exact) return exact;
    const prefixed = FIELD_SHEETS.find((sheet) => sheet.prefixes?.some((p) => ty.startsWith(p)));
    if (prefixed) return prefixed;
  }
  if (kind) return FIELD_SHEETS.find((sheet) => sheet.kinds?.includes(kind)) ?? null;
  return null;
}

export function sheetForRow(row: GridRow | null): FieldSheet {
  if (!row) return GENERIC_SHEET;
  const collection = row.ref.collection;
  if (collection !== "artifacts" && COLLECTION_SHEETS[collection]) {
    return COLLECTION_SHEETS[collection] as FieldSheet;
  }
  return sheetForType(row.artifactType, row.ref.kind) ?? GENERIC_SHEET;
}

// ---------------------------------------------------------------------------
// Classification of the remaining keys
// ---------------------------------------------------------------------------

/**
 * Governance / validation keys (tool self-assessment, not evidence): folded at the bottom as
 * "내부 검증 정보(증거 아님)".
 */
const GOVERNANCE_PATTERN =
  /(^|_)(commercial|validation|validations|blockers|readiness|grade|court_report|accuracy_gates|forensic_review|native_capabilities|uplift)(_|$)|_plan(_hash)?$|_plans?_|_manifest(_hash)?$|_review_profile(_hash)?$|_citation_profile(_hash)?$|_integrity_profile$|_depth_manifest|^recommended_validation|^artifact_record_contract$|_ready$|^ready_for_|_assessment$|^required_before_report$|^next_validation_step$/;

export function isGovernanceKey(key: string): boolean {
  return GOVERNANCE_PATTERN.test(key);
}

/** Provenance: where the record came from and how it was decoded. */
const PROVENANCE_PATTERN =
  /^(source_path|path|source_index|source_record_id|source_row_id|source_table|source_size|source_offset|source_length|source_locator|source_viewer_locator|source_format|source_files|source_hashes|source_hashes_by_file|record_offset|record_size|record_length|chunk_offset|cell_offset|hbin_offset|offset|length|end_offset|evtx_record_offset|evtx_record_size|evtx_record_sha256|evtx_chunk_index|entry_hint|relative_path|hashes|sha256|sha1|md5|row_hash|parser|parser_version|parser_confidence|confidence|coverage_status|evidence_strength|reportability|row_kind|kind|supported|pointer|recoverySourceId|deletionState|sourceOffset|recoveryInfo|recovery|sourceRecord|timestamp_source|timestamp_status|timestamp_timezone|timestamp_kind|timestamp_label|user_name_source|executable_hint_source|referenced_path_source|time_origin|modified_at_origin|source_file_mtime|source_file_ctime|source_file_atime|raw_preview|header_hex|record_projection|caution_labels|risk_flags|risk_score|scan_status|parser_error)$|_parse_status$|_decode_status$|_status_counts$|_truncated$|^truncated$|_100ns$|_filetime$|_filetimes$|_raw$|^evtx_.*_status$|^native_.*_status$/;

export function isProvenanceKey(key: string): boolean {
  return PROVENANCE_PATTERN.test(key);
}

/** Grid-derived fields the record view never lists (internal or shown elsewhere). */
const HIDDEN_KEYS = new Set([
  "highlight",
  "note",
  "includeInReport",
  "details",
  "artifact_record",
  "viewerMode",
  "isDirectory",
  "targetType",
  "event_tags_parsed",
]);

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

/** Words of humanised key labels. */
const WORDS: Record<string, string> = {
  id: "ID",
  ids: "ID 목록",
  url: "URL",
  urls: "URL 목록",
  ip: "IP",
  sid: "SID",
  rid: "RID",
  uri: "URI",
  guid: "GUID",
  usb: "USB",
  vid: "VID",
  pid: "PID",
  mru: "MRU",
  lnk: "LNK",
  evtx: "EVTX",
  mft: "MFT",
  usn: "USN",
  utc: "UTC",
  dll: "DLL",
  exe: "EXE",
  sha256: "SHA-256",
  sha1: "SHA-1",
  md5: "MD5",
  hash: "해시",
  hashes: "해시",
  name: "이름",
  names: "이름 목록",
  path: "경로",
  paths: "경로 목록",
  file: "파일",
  files: "파일",
  size: "크기",
  bytes: "바이트",
  time: "시각",
  times: "시각 목록",
  date: "날짜",
  type: "종류",
  types: "종류",
  kind: "종류",
  user: "사용자",
  users: "사용자",
  account: "계정",
  group: "그룹",
  groups: "그룹",
  value: "값",
  values: "값",
  data: "데이터",
  key: "키",
  keys: "키",
  count: "건수",
  total: "합계",
  status: "상태",
  state: "상태",
  source: "출처",
  target: "대상",
  host: "호스트",
  domain: "도메인",
  title: "제목",
  version: "버전",
  last: "마지막",
  first: "최초",
  created: "생성",
  modified: "수정",
  accessed: "접근",
  visit: "방문",
  visits: "방문",
  typed: "직접 입력",
  download: "다운로드",
  downloads: "다운로드",
  event: "이벤트",
  events: "이벤트",
  record: "레코드",
  records: "레코드",
  entry: "항목",
  entries: "항목",
  candidate: "후보",
  candidates: "후보",
  stream: "스트림",
  streams: "스트림",
  volume: "볼륨",
  volumes: "볼륨",
  serial: "시리얼",
  number: "번호",
  device: "장치",
  devices: "장치",
  process: "프로세스",
  command: "명령",
  line: "줄",
  logon: "로그온",
  session: "세션",
  rule: "규칙",
  rules: "규칙",
  risk: "위험",
  flags: "플래그",
  flag: "플래그",
  label: "라벨",
  labels: "라벨",
  offset: "오프셋",
  index: "순번",
  table: "테이블",
  row: "행",
  rows: "행",
  profile: "프로필",
  browser: "브라우저",
  machine: "머신",
  application: "앱",
  app: "앱",
  module: "모듈",
  code: "코드",
  exception: "예외",
  zone: "영역",
  referrer: "참조",
  transition: "전환",
  duration: "길이",
  micros: "µs",
  seconds: "초",
  ms: "ms",
  ole: "OLE",
  destlist: "DestList",
  destination: "대상",
  destinations: "대상",
  header: "헤더",
  content: "내용",
  entropy: "엔트로피",
  ratio: "비율",
  zero: "0 바이트",
  detected: "감지된",
  expected: "기대",
  actual: "실제",
  extension: "확장자",
  extensions: "확장자",
  signature: "서명",
  mismatch: "불일치",
  direction: "방향",
  hint: "추정",
  hints: "추정",
  summary: "요약",
  note: "참고",
  notes: "참고",
  trigger: "트리거",
  triggers: "트리거",
  action: "동작",
  actions: "동작",
  principal: "주체",
  principals: "주체",
  author: "작성자",
  task: "작업",
  hidden: "숨김",
  level: "수준",
  run: "실행",
  boundaries: "경계",
  layout: "배치",
  information: "정보",
  metrics: "지표",
  reference: "참조",
  references: "참조",
  referenced: "참조",
  decoded: "해석된",
  raw: "원문",
  preview: "미리보기",
  counts: "건수",
  top: "상위",
  inventory: "목록",
  storage: "저장소",
  ai: "AI",
  usage: "사용",
  internet: "인터넷",
  category: "분류",
  categories: "분류",
};

/** Suffix words that move to the end in Korean reading ("last_visit_time" → "마지막 방문 시각"). */
const SUFFIX_LABELS: Array<[RegExp, string]> = [
  [/_at$/, "시각"],
  [/_count$/, "건수"],
  [/_sha256$/, "SHA-256"],
  [/_sha1$/, "SHA-1"],
  [/_md5$/, "MD5"],
];

/** "danger_type_name" → "danger 종류 이름"; known suffixes (_at → 시각, _count → 건수 …). */
export function humanizeKey(key: string): string {
  let base = key;
  let tail = "";
  for (const [pattern, label] of SUFFIX_LABELS) {
    if (pattern.test(base) && base.replace(pattern, "") !== "") {
      tail = label;
      base = base.replace(pattern, "");
      break;
    }
  }
  const words = base
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .split(/[_\-.]+/)
    .filter(Boolean)
    .map((word) => WORDS[word.toLowerCase()] ?? word.toLowerCase());
  const out = [...words, tail].filter(Boolean).join(" ");
  return out || key;
}

/** Label of a key outside the sheet: its Korean label, else the humanised key. */
export function fieldLabel(key: string): string {
  return metaLabel(key) ?? humanizeKey(key);
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/** Logon events whose records carry LogonType / LogonId / IpAddress (4624 · 4625 · 4634 · 4647 · 4648 · 4672 · 4778 · 4779). */
const LOGON_EVENT_IDS = new Set(["4624", "4625", "4634", "4647", "4648", "4672", "4778", "4779"]);

export function isLogonEvent(fields: Record<string, unknown>): boolean {
  return LOGON_EVENT_IDS.has(flatValue(fields.event_id).trim());
}

export interface SheetEntry {
  /** The key shown (for derived values: the source, e.g. "event_data.TargetLogonId"). */
  key: string;
  label: string;
  raw: unknown;
  format: FieldFormat;
  /** Aliases of this fact present on the record and not shown (tooltip). */
  aliases: string[];
  timeKind?: string;
  /** Direct `details` key (artifact rows): it can be promoted to a grid column. */
  fromDetails: boolean;
  /** Derived from another field (EventData, a nested object). */
  derived?: boolean;
  /** An expected field the record does not carry ("레코드에 없음"). */
  missing?: boolean;
}

export interface RecordLayout {
  sheet: FieldSheet;
  core: SheetEntry[];
  /** Name/value table under 핵심 (EVTX EventData, registry values). */
  table: { key: string; label: string; rows: Array<{ name: string; value: unknown }> } | null;
  provenance: SheetEntry[];
  other: SheetEntry[];
  governance: SheetEntry[];
}

/** Every flat record field of a row: `fields.details` merged over the grid fields. */
export function layoutFields(row: GridRow | null): Record<string, unknown> {
  if (!row) return {};
  const { details, ...rest } = row.fields;
  const merged: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(rest)) {
    if (key === "artifact_record") continue;
    merged[key] = value;
  }
  if (isRecord(details)) Object.assign(merged, details);
  if (merged.channel === undefined && Array.isArray(merged.event_tags)) {
    const tag = merged.event_tags.find((item) => typeof item === "string" && item.startsWith("channel:"));
    if (typeof tag === "string") merged.channel = tag.slice("channel:".length);
  }
  // The grid's timestamp (first TIME_KEYS value) when the record has none of its own.
  if (merged.timestamp === undefined && row.timestamp && row.ref.collection !== "artifacts") {
    merged.timestamp = row.timestamp;
  }
  return merged;
}

function keysOf(def: FieldDef): readonly string[] {
  return typeof def.key === "string" ? [def.key] : def.key;
}

/** Same text (case-insensitive, whitespace-folded) — `detail` vs `event_message`, `eventId` vs `event_id`. */
function sameText(a: unknown, b: unknown): boolean {
  const norm = (v: unknown) => flatValue(v).replace(/\s+/g, " ").trim().toLowerCase();
  const x = norm(a);
  const y = norm(b);
  if (!x || !y) return false;
  // The grid summary is a clip of the message (leading "k=v |" segments dropped).
  const strip = (s: string) => s.replace(/…$/, "").replace(/^(?:\s*\w+=[^|]*\|)+\s*/, "");
  return x === y || strip(y).startsWith(strip(x)) || strip(x).startsWith(strip(y));
}

/** Grid summary keys that duplicate a record key: [grid key, record keys it restates]. */
const GRID_ALIASES: Array<[string, readonly string[]]> = [
  ["eventId", ["event_id"]],
  ["detail", ["message", "rendered_message", "event_message", "event_description", "summary", "title"]],
  ["matchedRules", ["rule", "rule_title", "rule_name"]],
  ["confidence", ["parser_confidence"]],
];

export function recordLayout(row: GridRow | null): RecordLayout {
  const sheet = sheetForRow(row);
  const fields = layoutFields(row);
  const details = row && isRecord(row.fields.details) ? row.fields.details : {};
  const used = new Set<string>();
  const suppressed = new Map<string, string>(); // alias key → shown key
  const core: SheetEntry[] = [];

  // Grid summary fields restating a record key are aliases of it.
  for (const [gridKey, recordKeys] of GRID_ALIASES) {
    if (!present(fields[gridKey]) || Object.hasOwn(details, gridKey)) continue;
    const twin = recordKeys.find((key) => present(fields[key]) && sameText(fields[gridKey], fields[key]));
    if (twin) suppressed.set(gridKey, twin);
  }
  // A flat sha256 equal to the container hash bundle's sha256 is the same fact.
  const bundle = isRecord(fields.source_hashes) ? fields.source_hashes : null;
  if (
    bundle &&
    present(fields.sha256) &&
    String(fields.sha256).toLowerCase() === String(bundle.sha256 ?? "").toLowerCase()
  ) {
    suppressed.set("sha256", "source_hashes");
  }

  for (const def of sheet.core) {
    const keys = keysOf(def);
    const hit = keys.find((key) => !used.has(key) && !suppressed.has(key) && present(fields[key]));
    if (hit) {
      const aliases = keys.filter(
        (key) => key !== hit && present(fields[key]) && sameText(fields[key], fields[hit]),
      );
      for (const key of [hit, ...aliases]) used.add(key);
      for (const key of aliases) suppressed.set(key, hit);
      core.push({
        key: hit,
        label: def.label,
        raw: fields[hit],
        format: def.format ?? "text",
        aliases,
        ...(def.timeKind ? { timeKind: def.timeKind } : {}),
        fromDetails: Object.hasOwn(details, hit),
      });
      continue;
    }
    const derived = def.derive?.(fields);
    if (derived && present(derived.value)) {
      core.push({
        key: derived.from,
        label: def.label,
        raw: derived.value,
        format: def.format ?? "text",
        aliases: [],
        ...(def.timeKind ? { timeKind: def.timeKind } : {}),
        fromDetails: false,
        derived: true,
      });
      continue;
    }
    if (def.expectWhen?.(fields)) {
      core.push({
        key: keys[0] as string,
        label: def.label,
        raw: null,
        format: def.format ?? "text",
        aliases: [],
        fromDetails: false,
        missing: true,
      });
    }
  }

  let table: RecordLayout["table"] = null;
  if (sheet.table) {
    for (const key of sheet.table.key) {
      const value = fields[key];
      const rows = tableRows(value);
      if (rows) {
        table = { key, label: sheet.table.label, rows };
        used.add(key);
        break;
      }
    }
  }

  // Native EVTX rows also copy System/EventData names to the top level (TargetUserName …):
  // a top-level key restating a table row is that row, shown once (in the table).
  if (table) {
    const byName = new Map(table.rows.map((r) => [r.name.toLowerCase(), r.value] as const));
    for (const [key, value] of Object.entries(fields)) {
      if (used.has(key) || suppressed.has(key) || key === table.key) continue;
      const twin = byName.get(key.toLowerCase());
      if (twin !== undefined && sameText(twin, value)) suppressed.set(key, table.key);
    }
  }

  const provenance: SheetEntry[] = [];
  const other: SheetEntry[] = [];
  const governance: SheetEntry[] = [];
  for (const [key, raw] of Object.entries(fields)) {
    if (used.has(key) || suppressed.has(key) || HIDDEN_KEYS.has(key) || !present(raw)) continue;
    const entry: SheetEntry = {
      key,
      label: fieldLabel(key),
      raw,
      format: "text",
      aliases: [],
      fromDetails: Object.hasOwn(details, key),
    };
    if (isGovernanceKey(key)) governance.push(entry);
    else if (isProvenanceKey(key)) provenance.push(entry);
    else other.push(entry);
  }
  // Aliases are named on the shown entry (tooltip), so nothing is silently dropped.
  for (const [alias, shown] of suppressed) {
    const target = [...core, ...provenance, ...other].find((entry) => entry.key === shown);
    if (target && !target.aliases.includes(alias)) target.aliases.push(alias);
  }
  provenance.sort((a, b) => provenanceRank(a.key) - provenanceRank(b.key));
  // Two keys outside the sheet that read the same label ("앱 이름" for application_name and
  // app_name) carry their raw key in the visible text (review B2-8).
  const all = [...core, ...provenance, ...other, ...governance];
  const uses = new Map<string, number>();
  for (const entry of all) uses.set(entry.label, (uses.get(entry.label) ?? 0) + 1);
  for (const entry of [...provenance, ...other, ...governance]) {
    if ((uses.get(entry.label) ?? 0) > 1) entry.label = `${entry.label} (${entry.key})`;
  }
  return { sheet, core, table, provenance, other, governance };
}

/** Name/value rows of an EventData-like map or a registry `values` list; null when it is neither. */
export function tableRows(value: unknown): Array<{ name: string; value: unknown }> | null {
  if (isRecord(value)) {
    const entries = Object.entries(value);
    return entries.length ? entries.map(([name, v]) => ({ name, value: v })) : null;
  }
  if (Array.isArray(value) && value.length && value.every(isRecord)) {
    return value.map((item, index) => {
      const record = item as Record<string, unknown>;
      const name =
        flatValue(record.name ?? record.value_name ?? record.Name ?? `#${index + 1}`) || "(기본값)";
      return { name, value: record };
    });
  }
  return null;
}

/** Provenance display order: path · locator/offsets · hashes · parser · decode state. */
const PROVENANCE_ORDER = [
  "source_path",
  "path",
  "relative_path",
  "entry_hint",
  "source_locator",
  "source_viewer_locator",
  "source_table",
  "source_row_id",
  "source_record_id",
  "source_index",
  "sourceRecord",
  "evtx_chunk_index",
  "evtx_record_offset",
  "evtx_record_size",
  "record_offset",
  "record_size",
  "source_offset",
  "cell_offset",
  "hbin_offset",
  "offset",
  "length",
  "source_size",
  "source_hashes",
  "sha256",
  "sha1",
  "md5",
  "evtx_record_sha256",
  "source_format",
  "parser",
  "parser_version",
  "coverage_status",
];

function provenanceRank(key: string): number {
  const index = PROVENANCE_ORDER.indexOf(key);
  if (index >= 0) return index;
  if (/_truncated$|^truncated$/.test(key)) return PROVENANCE_ORDER.length + 1;
  if (/_status$/.test(key)) return PROVENANCE_ORDER.length + 2;
  return PROVENANCE_ORDER.length + 3;
}

/** The record identifier for citations: the sheet's id keys, else the row locator. */
export function recordIdentifier(row: GridRow | null): { label: string; value: string } | null {
  if (!row) return null;
  const sheet = sheetForRow(row);
  const fields = layoutFields(row);
  for (const key of sheet.recordId ?? []) {
    if (present(fields[key])) {
      const label =
        key === "record_id" || key === "event_record_id"
          ? "EventRecordID"
          : /^(key|key_path|source_key_path)$/.test(key)
            ? "키 경로"
            : fieldLabel(key);
      return { label, value: flatValue(fields[key]) };
    }
  }
  return null;
}
