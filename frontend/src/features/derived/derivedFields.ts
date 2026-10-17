/**
 * Display-only catalogue columns (axiom-adoption §3.2, catalogue `derive:`): values the console
 * computes from the row's own fields — the event-log summary sentence (`event_summary_ko`), the
 * RDP direction (`rdp_direction`), the image EXIF state (`exif_status`) and the account auto-logon
 * flag (`auto_logon`). A deriver returns the value, `null` when the column does not apply to the row
 * (an RDP direction on a non-RDP event), or a reason when the parser does not give the input — the
 * grid then shows "없음 — <사유>" (docs/rapidtriage-known-limitations.md lists each one).
 */

import { flatValue } from "../../utils/flatValue";
import { logonTypeLabel } from "../viewer/fieldFormat";

export type DerivedValue = { value: string; detail?: string } | { missing: string } | null;

/** EVTX EventData containers (same list as viewer/fieldSheets EVENT_DATA_KEYS + the backend's). */
const EVENT_DATA_CONTAINERS = [
  "event_data",
  "data",
  "user_data",
  "binxml_event_data_values_by_name",
  "event_data_values_by_name",
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function scalar(value: unknown): string {
  if (Array.isArray(value) && value.length === 1) return scalar(value[0]);
  if (value === null || value === undefined || isRecord(value) || Array.isArray(value)) return "";
  const text = flatValue(value).trim();
  return text === "-" ? "" : text;
}

/** First non-empty value among `names`: a record key (snake case) or an EventData name (any case). */
export function fieldOf(fields: Record<string, unknown>, ...names: string[]): string {
  for (const name of names) {
    const own = scalar(fields[name]);
    if (own) return own;
  }
  for (const container of EVENT_DATA_CONTAINERS) {
    const data = fields[container];
    if (!isRecord(data)) continue;
    const lowered = new Map(Object.entries(data).map(([key, value]) => [key.toLowerCase(), value]));
    for (const name of names) {
      const hit = scalar(lowered.get(name.toLowerCase()));
      if (hit) return hit;
    }
  }
  return "";
}

// ---- event-log summary sentence ---------------------------------------------------------------

type Get = (...names: string[]) => string;

interface EventTemplate {
  id: string;
  /** Lower-case substrings of the channel or provider the template belongs to. */
  scope: readonly string[];
  text: (get: Get) => string;
}

const SECURITY = ["security"];
const SYSTEM_SCM = ["service control manager", "system"];
const LSM = ["terminalservices-localsessionmanager"];
const RCM = ["terminalservices-remoteconnectionmanager"];
const PS_OPERATIONAL = ["powershell/operational", "microsoft-windows-powershell"];
const PS_CLASSIC = ["windows powershell", "powershell"];
const DEFENDER = ["windows defender"];

const or = (value: string, fallback: string) => value || fallback;
const part = (prefix: string, value: string, suffix = "") => (value ? `${prefix}${value}${suffix}` : "");
const account = (get: Get, ...names: string[]) => or(get(...names), "(계정 미상)");
const subject = (get: Get) => get("subject_user_name", "SubjectUserName");
const target = (get: Get) => get("target_user_name", "TargetUserName");
const remote = (get: Get) => part(", 원격 ", get("source_ip", "IpAddress", "ClientAddress"));
const logon = (get: Get) => {
  const type = get("logon_type", "LogonType");
  return type ? ` (로그온 유형 ${logonTypeLabel(type)})` : "";
};
const by = (get: Get) => part(" — 계정 ", subject(get));
/** Security-audit message insertion strings (`%%23xx`) and NTSTATUS codes of failed logons. */
const LOGON_FAILURE_TEXT: Record<string, string> = {
  "%%2304": "로그온 중 오류",
  "%%2305": "지정한 계정이 없음",
  "%%2307": "계정 잠김",
  "%%2308": "로그온 유형이 허용되지 않음",
  "%%2309": "암호 만료",
  "%%2310": "계정 사용 안 함",
  "%%2311": "계정 만료",
  "%%2312": "이 컴퓨터에서 로그온할 수 없음",
  "%%2313": "알 수 없는 사용자 이름 또는 잘못된 암호",
  "0xc0000064": "없는 사용자 이름",
  "0xc000006a": "잘못된 암호",
  "0xc000006d": "잘못된 사용자 이름 또는 인증 정보",
  "0xc000006f": "허용 시간 외 로그온",
  "0xc0000070": "허용되지 않은 워크스테이션",
  "0xc0000071": "암호 만료",
  "0xc0000072": "계정 사용 안 함",
  "0xc0000193": "계정 만료",
  "0xc0000234": "계정 잠김",
  "0xc000015b": "허용되지 않은 로그온 유형",
};

function failureText(code: string): string {
  const known = LOGON_FAILURE_TEXT[code.trim().toLowerCase()];
  return known ? `${known}(${code})` : code;
}

const failure = (get: Get) => {
  const status = get("status_code", "Status");
  const sub = get("SubStatus");
  const reason = get("failure_reason", "FailureReason");
  const parts = [reason ? failureText(reason) : "", status ? `상태 ${failureText(status)}` : ""];
  if (sub && sub !== status && !/^0x0+$/i.test(sub)) parts.push(`세부 ${failureText(sub)}`);
  return part(" — ", parts.filter(Boolean).join(", "));
};
const member = (get: Get) => or(get("MemberName", "MemberSid"), "(구성원 미상)");
const shareTarget = (get: Get) => {
  const share = get("share_name", "ShareName");
  const relative = get("RelativeTargetName");
  return or([share, relative].filter(Boolean).join("\\"), "(공유 미상)");
};
const client = (get: Get) =>
  part(" (클라이언트 ", [get("ClientName"), get("ClientAddress")].filter(Boolean).join(" "), ")");
const rdpUser = (get: Get) => or(get("User", "user_name", "Param1"), "(사용자 미상)");
const rdpAddress = (get: Get) => part(" (주소 ", get("Address", "source_ip", "Param3"), ")");
const processPart = (get: Get) => part(", 프로세스 ", get("process_name", "ProcessName", "new_process_name"));

/** The 60 event IDs of the plan (§3.2), keyed by the channel / provider they belong to. */
export const EVENT_TEMPLATES: readonly EventTemplate[] = [
  // Security — logon / logoff
  {
    id: "4624",
    scope: SECURITY,
    text: (g) =>
      `계정 ${account(g, "target_user_name", "TargetUserName")} 로그온 성공${logon(g)}${remote(g)}`,
  },
  {
    id: "4625",
    scope: SECURITY,
    text: (g) =>
      `계정 ${account(g, "target_user_name", "TargetUserName")} 로그온 실패${logon(g)}${remote(g)}${failure(g)}`,
  },
  {
    id: "4634",
    scope: SECURITY,
    text: (g) => `계정 ${account(g, "target_user_name", "TargetUserName")} 로그오프${logon(g)}`,
  },
  {
    id: "4647",
    scope: SECURITY,
    text: (g) => `계정 ${account(g, "target_user_name", "TargetUserName")}이(가) 로그오프 시작`,
  },
  {
    id: "4648",
    scope: SECURITY,
    text: (g) =>
      `계정 ${account(g, "subject_user_name", "SubjectUserName")}이(가) 명시적 자격 증명으로 ${account(g, "target_user_name", "TargetUserName")} 로그온 시도${part(" — 대상 서버 ", g("TargetServerName"))}${processPart(g)}`,
  },
  {
    id: "4672",
    scope: SECURITY,
    text: (g) => `계정 ${account(g, "subject_user_name", "SubjectUserName")} 로그온에 특수 권한 할당`,
  },
  {
    id: "4688",
    scope: SECURITY,
    text: (g) =>
      `프로세스 생성: ${or(g("new_process_name", "NewProcessName", "process_name"), "(이름 미상)")}${part(" (부모 ", g("parent_process_name", "ParentProcessName"), ")")}${by(g)}`,
  },
  // Security — scheduled tasks, accounts, groups
  {
    id: "4698",
    scope: SECURITY,
    text: (g) => `예약 작업 생성: ${or(g("task_name", "TaskName"), "(작업 미상)")}${by(g)}`,
  },
  {
    id: "4702",
    scope: SECURITY,
    text: (g) => `예약 작업 변경: ${or(g("task_name", "TaskName"), "(작업 미상)")}${by(g)}`,
  },
  {
    id: "4720",
    scope: SECURITY,
    text: (g) => `계정 생성: ${account(g, "target_user_name", "TargetUserName")}${by(g)}`,
  },
  {
    id: "4722",
    scope: SECURITY,
    text: (g) => `계정 사용 설정: ${account(g, "target_user_name", "TargetUserName")}${by(g)}`,
  },
  {
    id: "4724",
    scope: SECURITY,
    text: (g) => `계정 암호 재설정 시도: ${account(g, "target_user_name", "TargetUserName")}${by(g)}`,
  },
  {
    id: "4726",
    scope: SECURITY,
    text: (g) => `계정 삭제: ${account(g, "target_user_name", "TargetUserName")}${by(g)}`,
  },
  {
    id: "4728",
    scope: SECURITY,
    text: (g) => `전역 보안 그룹 ${or(target(g), "(그룹 미상)")}에 구성원 추가: ${member(g)}${by(g)}`,
  },
  {
    id: "4732",
    scope: SECURITY,
    text: (g) => `로컬 보안 그룹 ${or(target(g), "(그룹 미상)")}에 구성원 추가: ${member(g)}${by(g)}`,
  },
  {
    id: "4756",
    scope: SECURITY,
    text: (g) => `유니버설 보안 그룹 ${or(target(g), "(그룹 미상)")}에 구성원 추가: ${member(g)}${by(g)}`,
  },
  // Security — Kerberos / NTLM
  {
    id: "4768",
    scope: SECURITY,
    text: (g) =>
      `Kerberos TGT 요청: 계정 ${account(g, "target_user_name", "TargetUserName")}${remote(g)}${failure(g)}`,
  },
  {
    id: "4769",
    scope: SECURITY,
    text: (g) =>
      `Kerberos 서비스 티켓 요청: ${or(g("service_name", "ServiceName"), "(서비스 미상)")} — 계정 ${account(g, "target_user_name", "TargetUserName")}${remote(g)}`,
  },
  {
    id: "4771",
    scope: SECURITY,
    text: (g) =>
      `Kerberos 사전 인증 실패: 계정 ${account(g, "target_user_name", "TargetUserName")}${remote(g)}${failure(g)}`,
  },
  {
    id: "4776",
    scope: SECURITY,
    text: (g) => {
      const status = g("status_code", "Status");
      const failed = status && !/^0x0+$/i.test(status) && status !== "0";
      return `NTLM 자격 증명 확인${failed ? " 실패" : ""}: 계정 ${account(g, "target_user_name", "TargetUserName")}${part(" (워크스테이션 ", g("workstation_name", "Workstation"), ")")}${failed ? ` — 상태 ${status}` : ""}`;
    },
  },
  {
    id: "4778",
    scope: SECURITY,
    text: (g) => `세션 재연결: 계정 ${account(g, "AccountName", "target_user_name")}${client(g)}`,
  },
  {
    id: "4779",
    scope: SECURITY,
    text: (g) => `세션 연결 끊김: 계정 ${account(g, "AccountName", "target_user_name")}${client(g)}`,
  },
  // Security — log, services, shares, objects
  { id: "1102", scope: SECURITY, text: (g) => `보안 로그 지움${by(g)}` },
  {
    id: "4697",
    scope: SECURITY,
    text: (g) =>
      `서비스 설치(보안 감사): ${or(g("service_name", "ServiceName"), "(서비스 미상)")}${part(" — ", g("service_file_name", "ServiceFileName"))}${by(g)}`,
  },
  {
    id: "5140",
    scope: SECURITY,
    text: (g) => `네트워크 공유 접근: ${or(g("share_name", "ShareName"), "(공유 미상)")}${by(g)}${remote(g)}`,
  },
  {
    id: "5145",
    scope: SECURITY,
    text: (g) => `네트워크 공유 개체 접근 검사: ${shareTarget(g)}${by(g)}${remote(g)}`,
  },
  {
    id: "4663",
    scope: SECURITY,
    text: (g) => `개체 접근: ${or(g("target_object", "ObjectName"), "(개체 미상)")}${by(g)}${processPart(g)}`,
  },
  {
    id: "4656",
    scope: SECURITY,
    text: (g) =>
      `개체 핸들 요청: ${or(g("target_object", "ObjectName"), "(개체 미상)")}${by(g)}${processPart(g)}`,
  },
  // System
  {
    id: "104",
    scope: ["microsoft-windows-eventlog", "system"],
    text: (g) => `이벤트 로그 지움${part(": ", g("Channel", "BackupPath"))}${by(g)}`,
  },
  {
    id: "7045",
    scope: SYSTEM_SCM,
    text: (g) =>
      `서비스 설치: ${or(g("service_name", "ServiceName"), "(서비스 미상)")}${part(" — ", g("service_file_name", "ImagePath"))}${part(" (계정 ", g("service_account_name", "AccountName"), ")")}`,
  },
  {
    id: "7034",
    scope: SYSTEM_SCM,
    text: (g) => `서비스가 예기치 않게 종료됨: ${or(g("service_name", "param1", "Param1"), "(서비스 미상)")}`,
  },
  {
    id: "7036",
    scope: SYSTEM_SCM,
    text: (g) =>
      `서비스 ${or(g("service_name", "param1", "Param1"), "(서비스 미상)")} 상태 변경${part(": ", g("param2", "Param2"))}`,
  },
  { id: "6005", scope: ["eventlog", "system"], text: () => "이벤트 로그 서비스 시작(부팅)" },
  { id: "6006", scope: ["eventlog", "system"], text: () => "이벤트 로그 서비스 중지(정상 종료)" },
  { id: "6008", scope: ["eventlog", "system"], text: () => "이전 시스템 종료가 예기치 않게 일어남" },
  {
    id: "41",
    scope: ["kernel-power"],
    text: () => "시스템이 정상 종료 없이 다시 시작됨(전원 손실·강제 종료 가능)",
  },
  { id: "12", scope: ["kernel-general"], text: () => "운영 체제 시작" },
  { id: "13", scope: ["kernel-general"], text: () => "운영 체제 종료" },
  {
    id: "20001",
    scope: ["userpnp"],
    text: (g) =>
      `장치 드라이버 설치${part(": ", g("device_instance_id", "DeviceInstanceID", "DeviceInstanceId"))}`,
  },
  {
    id: "20003",
    scope: ["userpnp"],
    text: (g) => `장치 서비스 추가${part(": ", g("service_name", "ServiceName", "DriverName"))}`,
  },
  // Remote Desktop
  { id: "21", scope: LSM, text: (g) => `원격 데스크톱 세션 로그온: ${rdpUser(g)}${rdpAddress(g)}` },
  { id: "22", scope: LSM, text: (g) => `원격 데스크톱 셸 시작: ${rdpUser(g)}${rdpAddress(g)}` },
  { id: "23", scope: LSM, text: (g) => `원격 데스크톱 세션 로그오프: ${rdpUser(g)}` },
  { id: "24", scope: LSM, text: (g) => `원격 데스크톱 세션 연결 끊김: ${rdpUser(g)}${rdpAddress(g)}` },
  { id: "25", scope: LSM, text: (g) => `원격 데스크톱 세션 재연결: ${rdpUser(g)}${rdpAddress(g)}` },
  {
    id: "40",
    scope: LSM,
    text: (g) => `세션 ${or(g("Session", "SessionID"), "?")} 연결 끊김${part(" — 사유 코드 ", g("Reason"))}`,
  },
  { id: "41", scope: LSM, text: (g) => `원격 데스크톱 세션 중재 시작: ${rdpUser(g)}` },
  {
    id: "1149",
    scope: RCM,
    text: (g) =>
      `원격 데스크톱 네트워크 인증 성공: ${or(g("Param1", "user_name"), "(사용자 미상)")}${part("@", g("Param2"))}${part(" (주소 ", g("Param3", "source_ip"), ")")}`,
  },
  // PowerShell
  { id: "4100", scope: PS_OPERATIONAL, text: () => "PowerShell 오류 기록" },
  {
    id: "4103",
    scope: PS_OPERATIONAL,
    text: (g) => `PowerShell 모듈 로깅(명령 실행)${part(": ", g("CommandName"))}`,
  },
  {
    id: "4104",
    scope: PS_OPERATIONAL,
    text: (g) => `PowerShell 스크립트 블록 실행 기록${part(": ", g("Path"))}`,
  },
  { id: "400", scope: PS_CLASSIC, text: () => "PowerShell 엔진 시작" },
  { id: "403", scope: PS_CLASSIC, text: () => "PowerShell 엔진 종료" },
  { id: "800", scope: PS_CLASSIC, text: () => "PowerShell 파이프라인 실행 기록" },
  // Defender
  {
    id: "1116",
    scope: DEFENDER,
    text: (g) =>
      `악성코드 탐지: ${or(g("Threat Name", "ThreatName"), "(이름 미상)")}${part(" — ", g("Path"))}`,
  },
  {
    id: "1117",
    scope: DEFENDER,
    text: (g) =>
      `악성코드 대응 조치: ${or(g("Threat Name", "ThreatName"), "(이름 미상)")}${part(" — ", g("Action Name", "ActionName"))}`,
  },
  { id: "5001", scope: DEFENDER, text: () => "Defender 실시간 보호 꺼짐" },
  {
    id: "5007",
    scope: DEFENDER,
    text: (g) => `Defender 설정 변경${part(": ", g("New Value", "NewValue"))}`,
  },
  // Application
  {
    id: "1000",
    scope: ["application error", "application"],
    text: (g) =>
      `응용 프로그램 오류: ${or(g("AppName", "param1", "Param1"), "(앱 미상)")}${part(" — 오류 모듈 ", g("ModuleName", "param4"))}`,
  },
  {
    id: "1001",
    scope: ["windows error reporting", "application"],
    text: (g) => `오류 보고(WER)${part(": ", g("EventName", "param1"))}`,
  },
];

/** IDs with a template (the plan's list of 60; 41 appears twice: Kernel-Power and LSM). */
export const EVENT_TEMPLATE_IDS: readonly string[] = [...new Set(EVENT_TEMPLATES.map((t) => t.id))];

const BY_ID = new Map<string, EventTemplate[]>();
for (const template of EVENT_TEMPLATES) BY_ID.set(template.id, [...(BY_ID.get(template.id) ?? []), template]);

function eventId(fields: Record<string, unknown>): string {
  const text = fieldOf(fields, "event_id", "eventId", "EventID");
  return text.split(".")[0] ?? "";
}

/** Korean summary sentence of an event-log record; "요약 없음 (ID n)" when no template applies. */
export function eventSummaryKo(fields: Record<string, unknown>): string {
  const id = eventId(fields);
  if (!id) return "요약 없음 (ID 없음)";
  const where =
    `${fieldOf(fields, "channel", "Channel")}\n${fieldOf(fields, "provider_name", "ProviderName", "provider")}`.toLowerCase();
  const template = BY_ID.get(id)?.find((candidate) => candidate.scope.some((scope) => where.includes(scope)));
  if (!template) return `요약 없음 (ID ${id})`;
  const get: Get = (...names) => fieldOf(fields, ...names);
  return template.text(get);
}

// ---- RDP direction --------------------------------------------------------------------------

export const RDP_INBOUND = "인바운드(이 PC로 접속)";
export const RDP_OUTBOUND = "아웃바운드(이 PC에서 접속)";

/** Direction of an RDP record: inbound session / network-auth events, outbound client events and MRU. */
export function rdpDirection(fields: Record<string, unknown>, artifactType: string): string | null {
  if (artifactType.startsWith("rdp-")) return RDP_OUTBOUND; // Terminal Server Client MRU (this PC → server)
  const id = eventId(fields);
  if (!id) return null;
  const channel =
    `${fieldOf(fields, "channel", "Channel")} ${fieldOf(fields, "provider_name", "ProviderName")}`.toLowerCase();
  if (channel.includes("terminalservices-rdpclient"))
    return ["1024", "1102", "1029", "1026"].includes(id) ? RDP_OUTBOUND : null;
  if (channel.includes("terminalservices-localsessionmanager"))
    return ["21", "22", "23", "24", "25", "39", "40", "41"].includes(id) ? RDP_INBOUND : null;
  if (channel.includes("terminalservices-remoteconnectionmanager")) return id === "1149" ? RDP_INBOUND : null;
  if (channel.includes("rdpcorets")) return ["131", "98"].includes(id) ? RDP_INBOUND : null;
  if (channel.includes("security")) {
    if (id === "4778" || id === "4779") return RDP_INBOUND;
    if ((id === "4624" || id === "4625") && fieldOf(fields, "logon_type", "LogonType") === "10")
      return RDP_INBOUND;
  }
  return null;
}

// ---- EXIF state ----------------------------------------------------------------------------

export const EXIF_DONE = "완료";
export const EXIF_NONE = "없음";
export const EXIF_ERROR = "오류";

/** EXIF extraction state of an image row from the parser's `exif_gps_profile` / decode state. */
export function exifStatus(fields: Record<string, unknown>, artifactType: string): DerivedValue {
  const decode = scalar(fields.decode_status).toLowerCase();
  if (artifactType === "media-image-unreadable" || /error|fail|unreadable/.test(decode)) {
    return { value: EXIF_ERROR, detail: decode || artifactType };
  }
  const profile = fields.exif_gps_profile;
  if (!isRecord(profile)) {
    if (artifactType === "media-video" || artifactType === "media-audio")
      return { missing: "동영상·오디오에는 EXIF 추출을 하지 않음" };
    if (scalar(fields.exif_make) || scalar(fields.exif_datetime_original)) return { value: EXIF_DONE };
    return { missing: "파서가 EXIF 추출 상태를 남기지 않음" };
  }
  const status = scalar(profile.status).toLowerCase();
  if (/error|fail/.test(status)) return { value: EXIF_ERROR, detail: status };
  if (status === "no-exif" || profile.exif_block_empty === true) return { value: EXIF_NONE, detail: status };
  if (
    profile.exif_block_present === true ||
    profile.has_exif === true ||
    status === "parsed" ||
    status.startsWith("no-gps")
  )
    return { value: EXIF_DONE, detail: status };
  return status ? { value: EXIF_NONE, detail: status } : { missing: "EXIF 상태 값이 비어 있음" };
}

// ---- registry ---------------------------------------------------------------------------------

export const AUTO_LOGON_REASON = "파서 미지원(Winlogon AutoAdminLogon 값이 계정 행에 연결되지 않음)";

/**
 * Deriver of a catalogue column by its `derive` id; `fields` = the row's details, `artifactType` its
 * type. Unknown ids read as a missing value with the reason (never a silent blank).
 */
export function deriveColumn(
  id: string,
  fields: Record<string, unknown>,
  artifactType: string,
): DerivedValue {
  switch (id) {
    case "event_summary_ko": {
      if (!fieldOf(fields, "event_id", "eventId", "EventID")) return { missing: "이벤트 ID 없음" };
      return { value: eventSummaryKo(fields) };
    }
    case "rdp_direction": {
      const direction = rdpDirection(fields, artifactType);
      return direction ? { value: direction } : null;
    }
    case "exif_status":
      return exifStatus(fields, artifactType);
    case "auto_logon":
      return { missing: AUTO_LOGON_REASON };
    default:
      return { missing: `알 수 없는 파생 열(${id})` };
  }
}

/** "없음 — <사유>" of a missing derived value. */
export function missingText(reason: string): string {
  return `없음 — ${reason}`;
}
