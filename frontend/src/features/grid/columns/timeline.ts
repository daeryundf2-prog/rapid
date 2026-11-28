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
import { timelineTarget } from "./timelineTarget";

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
 * Korean names of event-log categories (`eventlog-<category>` events; rapidtriage
 * artifacts/windows/eventlog.py EVENT_CATEGORY_TABLE).
 */
export const EVENTLOG_CATEGORY_LABELS: Readonly<Record<string, string>> = {
  "account-locked": "계정 잠김",
  "audit-log-cleared": "감사 로그 지움",
  "audit-policy-changed": "감사 정책 변경",
  "computer-created": "컴퓨터 계정 생성",
  "credential-validation": "자격 증명 확인",
  "defender-config-changed": "Defender 설정 변경",
  "defender-malware-detected": "Defender 악성코드 탐지",
  "defender-realtime-protection-disabled": "Defender 실시간 보호 끔",
  "defender-remediation-action": "Defender 조치",
  "domain-policy-changed": "도메인 정책 변경",
  "eventlog-service-shutdown": "이벤트 로그 서비스 종료",
  "explicit-credential-logon": "명시적 자격 증명 로그온",
  "external-device-recognized": "외부 장치 인식",
  "firewall-bind-allowed": "방화벽 바인드 허용",
  "firewall-connection-allowed": "방화벽 연결 허용",
  "firewall-rule-added": "방화벽 규칙 추가",
  "firewall-rule-deleted": "방화벽 규칙 삭제",
  "firewall-rule-modified": "방화벽 규칙 변경",
  "group-member-added": "전역 그룹 구성원 추가",
  "kerberos-preauth-failure": "Kerberos 사전 인증 실패",
  "kerberos-service-ticket": "Kerberos 서비스 티켓 요청",
  "kerberos-tgt-request": "Kerberos TGT 요청",
  "local-group-member-added": "로컬 그룹 구성원 추가",
  logoff: "로그오프",
  "logon-failure": "로그온 실패",
  "logon-success": "로그온 성공",
  "network-share-accessed": "네트워크 공유 접근",
  "network-share-detailed-access": "네트워크 공유 세부 접근 확인",
  "password-reset": "암호 재설정 시도",
  "powershell-module": "PowerShell 모듈 로그",
  "powershell-script-block": "PowerShell 스크립트 블록",
  "privileged-logon": "특수 권한 로그온",
  "process-created": "프로세스 생성",
  "rdp-authentication-succeeded": "원격 데스크톱 인증 성공",
  "rdp-session-disconnected": "원격 데스크톱 세션 연결 끊김",
  "rdp-session-logoff": "원격 데스크톱 세션 로그오프",
  "rdp-session-logon": "원격 데스크톱 세션 로그온",
  "rdp-session-reconnected": "원격 데스크톱 세션 재연결",
  "rdp-shell-start": "원격 데스크톱 셸 시작",
  "scheduled-task-completed": "예약 작업 완료",
  "scheduled-task-created": "예약 작업 생성",
  "scheduled-task-deleted": "예약 작업 삭제",
  "scheduled-task-disabled": "예약 작업 사용 안 함",
  "scheduled-task-enabled": "예약 작업 사용",
  "scheduled-task-registered": "예약 작업 등록",
  "scheduled-task-started": "예약 작업 시작",
  "scheduled-task-updated": "예약 작업 변경",
  "security-log-full": "보안 로그 가득 참",
  "service-crashed": "서비스 비정상 종료",
  "service-installed": "서비스 설치",
  "service-start-type-changed": "서비스 시작 유형 변경",
  "service-state-changed": "서비스 상태 변경",
  "session-disconnected": "세션 연결 끊김",
  "session-reconnected": "세션 재연결",
  "sysmon-dns-query": "Sysmon DNS 조회",
  "sysmon-file-created": "Sysmon 파일 생성",
  "sysmon-image-loaded": "Sysmon 이미지 로드",
  "sysmon-network-connection": "Sysmon 네트워크 연결",
  "sysmon-process-created": "Sysmon 프로세스 생성",
  "sysmon-registry-value-set": "Sysmon 레지스트리 값 설정",
  "system-log-cleared": "이벤트 로그 지움",
  "system-time-changed": "시스템 시각 변경",
  "universal-group-member-added": "유니버설 그룹 구성원 추가",
  "user-changed": "사용자 계정 변경",
  "user-created": "사용자 계정 생성",
  "user-deleted": "사용자 계정 삭제",
  "user-disabled": "사용자 계정 사용 안 함",
  "user-enabled": "사용자 계정 사용",
  "user-initiated-logoff": "사용자 로그오프",
  "wmi-activity": "WMI 공급자 시작",
  "wmi-activity-error": "WMI 활동 오류",
  "wmi-permanent-event": "WMI 영구 이벤트 소비자 활동",
  "workstation-locked": "워크스테이션 잠금",
  "workstation-unlocked": "워크스테이션 잠금 해제",
  "recovery-candidate": "복구 후보",
};

const EVENTLOG_PREFIX = "eventlog-";
const ARTIFACT_PREFIX = "artifact-";

/** "EVTX 이벤트 · 로그온 성공" for `eventlog-<category>`; null for another id or an unnamed category. */
function eventlogLabel(eventType: string): string | null {
  if (!eventType.startsWith(EVENTLOG_PREFIX)) return null;
  const category = EVENTLOG_CATEGORY_LABELS[eventType.slice(EVENTLOG_PREFIX.length)];
  return category ? `${artifactTypeLabel("eventlog-event") ?? "이벤트 로그"} · ${category}` : null;
}

/**
 * Korean reading of a timeline event type: its own Korean name (eventlog-event …); a files event
 * (`file-<kind>`) as 파일 · kind; an event-log event as EVTX 이벤트 · category; else the Korean
 * name of the artifact row it came from plus the time kind its id carries
 * (`artifact-<type>-<kind>`, core/timeline.py: `artifact-jumplist-automatic-target-accessed` →
 * "자동 Jump List 파일 · 대상 접근"). `sourceType` is the row's `details.artifact_type`; without
 * it (action dialogs list bare ids) the longest named type the id starts with is used. Else the id.
 * The kind stays in the text: 시각 종류 is not a 분석 기본 column, and two events of one record
 * (생성 / 수정) must not read the same.
 */
export function eventTypeLabel(eventType: string, sourceType?: string | null): string {
  if (!eventType) return "";
  const own = artifactTypeLabel(eventType) ?? DOCUMENT_EVENT_LABELS[eventType];
  if (own) return own;
  if (eventType.startsWith("file-")) return `파일 · ${timestampKindLabel(eventType.slice("file-".length))}`;
  const eventlog = eventlogLabel(eventType);
  if (eventlog) return eventlog;
  const sourceLabel = sourceType ? artifactTypeLabel(sourceType) : null;
  if (sourceType && sourceLabel) {
    const prefix = `${ARTIFACT_PREFIX}${sourceType}-`;
    const kind = eventType.startsWith(prefix) ? eventType.slice(prefix.length) : "";
    return kind ? `${sourceLabel} · ${timestampKindLabel(kind)}` : sourceLabel;
  }
  if (eventType.startsWith(ARTIFACT_PREFIX)) {
    const parts = eventType.slice(ARTIFACT_PREFIX.length).split("-");
    for (let cut = parts.length - 1; cut >= 1; cut -= 1) {
      const label = artifactTypeLabel(parts.slice(0, cut).join("-"));
      if (label) return `${label} · ${timestampKindLabel(parts.slice(cut).join("-"))}`;
    }
  }
  return eventType;
}

/** 이벤트 column text of a timeline row (`eventTypeLabel` with the row's source artifact type). */
export function timelineEventLabel(row: GridRow): string {
  return eventTypeLabel(row.artifactType ?? "", str(row.fields.sourceArtifactType) || null);
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
    // 대상 (F10): the event's target from its structured fields, not "Artifact event: <family> …".
    const target = timelineTarget(raw);
    return makeRow(
      makeRef("timeline", `/events/${index}`),
      {
        title: target.text || `이벤트 ${index + 1}`,
        sourcePath: timelinePathOf(raw),
        timestamp: strOrNull(raw.timestamp),
        artifactType: strOrNull(raw.event_type),
        provider: strOrNull(raw.source),
      },
      {
        source: str(raw.source),
        eventType: str(raw.event_type),
        // The generated summary, whole (the 대상 tooltip and the record view keep it).
        summary: str(raw.summary),
        targetTitle: target.title,
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
      // Default ≈ minimum: the width a time no longer needs goes to 요약 (it flexes).
      ...col.timestamp(146, ["analysis", "compact", "source"]),
      // The narrowest "2026-10-18 08:02:48" reads whole at 13px (126px text + padding; the
      // header names the zone); a narrow pane keeps 요약 beside it (fe-audit A5).
      minWidth: 144,
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
    // 대상 (F10): file name / URL host+path / executable / key first; the full target and the
    // original summary on hover. 390: 시각 (144) and 대상 share the pane without cutting the time.
    { ...col.title("대상", 380), minWidth: 100, tooltip: (r) => str(r.fields.targetTitle) || r.title },
    col.review(),
    // The event's own file: whole path, the leading folders ellipsize and the file name stays.
    col.path(420, ["analysis", "source"]),
  ],
  // A narrow pane keeps what happened next to when (fe-audit A5): 시각 > 대상 > 이벤트 > 시각 종류 > 출처 > 판정 > 경로.
  widthPriority: () => TIMELINE_PRIORITY,
};
