/**
 * 탐색 domain tree (console-ia §4): forensic domains → nodes, one mapping line per node.
 *
 * A node maps to a collection view and its server filters: an artifact `kind`, repeated
 * `artifact_type` values of that kind (sent as `artifact_type=`; a typed node ALWAYS carries
 * its kind so the server pages one kind — a type emitted by two kinds gets one node per
 * kind), file extensions (`ext=`) or an
 * analysis node (job results, `#/case/{run}/explore/analysis/{node}`). Only nodes that map
 * to data the engine produces today are listed (P4 completes the table); a node whose
 * count is known to be 0 is dimmed with a reason, an unknown count shows "—".
 */

import type { CollectionId } from "../../contracts/collection";
import type { IconName } from "../../icons";
import type { AnalysisNodeId } from "../analysis/kinds";

export interface DomainTarget {
  collection: CollectionId;
  kind?: string;
  /** Server `artifact_type=` filter (route `types=`). */
  types?: string[];
  /** File extensions (route `ext=`, applied to loaded rows). */
  ext?: string[];
  /** Server files category (`GET /files?category=<id>`, route `category=`; `/tree` node `files:<id>`). */
  fileCategory?: string;
  /** Analysis results node (collection "analysis"). */
  analysis?: AnalysisNodeId;
}

export interface DomainNodeDef {
  id: string;
  label: string;
  target: DomainTarget;
  icon?: IconName;
  /**
   * Rows that are not evidence records (`*-string-candidate` pivots): the node stays listed but
   * dimmed with NON_EVIDENCE_NOTE, and its count never adds to the domain total.
   */
  nonEvidence?: boolean;
  /**
   * Cross-listing of a type whose primary node lives in another domain (자동 실행/지속성 also
   * under 침해사고): same request, not the type's primary node.
   */
  crossRef?: boolean;
  /**
   * Bulk / auxiliary rows (레지스트리 키 트리, Prefetch 참조 경로, 브라우저 수집 오류): listed and
   * openable, but left out of the domain total so the main counts are evidence records.
   */
  detail?: boolean;
  /** Korean names of the node's types when it maps several (유형 filter list). */
  typeLabels?: Readonly<Record<string, string>>;
}

/** Tooltip of a non-evidence node (string pivots the parser could not tie to a record). */
export const NON_EVIDENCE_NOTE =
  "문자열 후보 — 레코드 구조로 해석되지 않은 문자열 피벗입니다. 증거 레코드가 아니므로 개수 합계에서 뺍니다.";

export interface DomainDef {
  id: string;
  label: string;
  icon: IconName;
  nodes: DomainNodeDef[];
}

const a = (kind: string, types?: string[]): DomainTarget =>
  types ? { collection: "artifacts", kind, types } : { collection: "artifacts", kind };
const files = (category: string): DomainTarget => ({ collection: "files", fileCategory: category });
const run = (analysis: AnalysisNodeId): DomainTarget => ({
  collection: "analysis",
  kind: analysis,
  analysis,
});

/**
 * The 15 forensic domains of console-ia §4 (증거 소스 is the evidence node built from the
 * dashboard). Domain ids match the server tree groups (`artifacts-group:<domain>`, api/app/tree.py
 * ARTIFACT_DOMAIN_TABLE): a kind whose types the server routes to another domain shows there as
 * `artifacts:<kind>@<domain>`; counts come from every kind node of the kind (model.ts).
 *
 * Every evidence type of the parser-quality r1 data model has exactly one primary node here
 * (domainMapping.test.ts); `crossRef` nodes repeat a type in a second domain.
 */
export const DOMAINS: readonly DomainDef[] = [
  {
    id: "os",
    label: "운영체제·계정",
    icon: "cpu",
    nodes: [
      {
        id: "os-accounts",
        label: "사용자·그룹(SAM)",
        target: a("windows-os-account", [
          "windows-sam-account",
          "windows-sam-group",
          "windows-sam-account-candidate",
          "windows-sam-group-candidate",
        ]),
        typeLabels: {
          "windows-sam-account": "SAM 계정",
          "windows-sam-group": "SAM 그룹",
          "windows-sam-account-candidate": "SAM 계정(reg 내보내기)",
          "windows-sam-group-candidate": "SAM 그룹(reg 내보내기)",
        },
      },
      { id: "os-system", label: "시스템 정보(Windows)", target: a("windows-system") },
      {
        id: "os-sysinfo",
        label: "시스템 정보(레지스트리)",
        target: a("windows-registry", [
          "windows-timezone",
          "windows-computer-name",
          "windows-os-version",
          "windows-control-set",
          "windows-network-interface",
          "windows-profile-list-entry",
          "windows-installed-program",
        ]),
        typeLabels: {
          "windows-timezone": "시간대",
          "windows-computer-name": "컴퓨터 이름",
          "windows-os-version": "OS 버전",
          "windows-control-set": "ControlSet",
          "windows-network-interface": "네트워크 인터페이스",
          "windows-profile-list-entry": "사용자 프로필 목록",
          "windows-installed-program": "설치 프로그램(레지스트리)",
        },
      },
      { id: "os-linux", label: "Linux 시스템", target: a("linux-system") },
      { id: "os-macos", label: "macOS 시스템", target: a("macos-system") },
      { id: "os-installed", label: "설치 프로그램(Windows)", target: a("windows-system", ["uwp-package"]) },
      { id: "os-installed-linux", label: "설치 패키지(Linux)", target: a("linux-system", ["linux-package"]) },
      { id: "os-tasks", label: "작업 스케줄러", target: a("windows-system", ["task-scheduler-task"]) },
      { id: "os-tasks-linux", label: "cron(Linux)", target: a("linux-system", ["linux-cron-entry"]) },
      {
        id: "os-services",
        label: "서비스(Windows)",
        target: a("windows-registry", ["windows-service-config"]),
      },
      {
        id: "os-services-export",
        label: "서비스(reg 내보내기)",
        target: a("windows-os-account", ["windows-service-config"]),
      },
      {
        id: "os-services-linux",
        label: "서비스(Linux systemd)",
        target: a("linux-system", ["linux-systemd-service"]),
      },
      { id: "os-wer", label: "WER", target: a("windows-system", ["wer-report"]) },
    ],
  },
  {
    id: "execution",
    label: "실행 흔적",
    icon: "play",
    nodes: [
      { id: "exec-prefetch", label: "Prefetch", target: a("windows-prefetch", ["prefetch-file"]) },
      {
        id: "exec-prefetch-invalid",
        label: "손상/비정상 Prefetch",
        target: a("windows-prefetch", ["prefetch-invalid-content"]),
      },
      {
        id: "exec-prefetch-refs",
        label: "Prefetch 참조 경로",
        target: a("windows-prefetch", ["prefetch-reference"]),
        detail: true,
      },
      { id: "exec-all", label: "실행 흔적 전체", target: a("windows-execution") },
      {
        id: "exec-amcache",
        label: "Amcache/ShimCache",
        target: a("windows-execution", ["amcache-schema-row", "shimcache-schema-entry"]),
        typeLabels: { "amcache-schema-row": "Amcache", "shimcache-schema-entry": "ShimCache" },
      },
      {
        id: "exec-bam",
        label: "UserAssist/BAM",
        target: a("windows-execution", ["bam-schema-entry", "userassist-schema-entry"]),
        typeLabels: { "bam-schema-entry": "BAM", "userassist-schema-entry": "UserAssist" },
      },
      {
        id: "exec-strings",
        label: "문자열 후보(증거 아님)",
        target: a("windows-execution", [
          "amcache-string-candidate",
          "shimcache-string-candidate",
          "bam-string-candidate",
        ]),
        nonEvidence: true,
      },
      {
        id: "exec-lnk",
        label: "LNK/Jump List",
        target: a("recent-files", ["recent-shortcut", "shell-shortcut", "jumplist-entry"]),
        typeLabels: {
          "recent-shortcut": "최근 항목 바로가기",
          "shell-shortcut": "바탕화면·시작 메뉴 바로가기",
          "jumplist-entry": "Jump List 항목",
        },
      },
      {
        id: "exec-jumplist-files",
        label: "Jump List 파일",
        target: a("recent-files", ["jumplist-automatic", "jumplist-custom"]),
        detail: true,
      },
      {
        id: "exec-lnk-invalid",
        label: "비정상 바로가기",
        target: a("recent-files", ["recent-shortcut-invalid-content", "shell-shortcut-invalid-content"]),
      },
      { id: "exec-search-index", label: "Windows 검색 색인", target: a("windows-search-index") },
      {
        id: "exec-powershell",
        label: "PowerShell 히스토리",
        target: a("windows-execution", ["powershell-history-command"]),
      },
      {
        id: "exec-srum",
        label: "SRUM",
        target: a("windows-execution", ["srum-row-candidate", "srum-database-file"]),
      },
    ],
  },
  {
    id: "filesystem",
    label: "파일시스템",
    icon: "hard-drive",
    nodes: [
      { id: "fs-all", label: "전체 파일", target: { collection: "files" } },
      { id: "fs-documents", label: "문서", target: files("documents") },
      { id: "fs-images", label: "이미지", target: files("images") },
      { id: "fs-archives", label: "압축", target: files("archives") },
      { id: "fs-databases", label: "데이터베이스", target: files("databases") },
      { id: "fs-emails", label: "이메일 파일", target: files("emails") },
      { id: "fs-other", label: "기타", target: files("other") },
      { id: "fs-mft", label: "MFT/USN", target: run("ntfs-meta") },
      { id: "fs-carve", label: "복구/카빙", target: run("carve") },
      { id: "fs-vsc", label: "볼륨 섀도우", target: run("vsc") },
      { id: "fs-recycle", label: "삭제/휴지통", target: a("windows-filesystem", ["recycle-bin-entry"]) },
      {
        id: "fs-mismatch",
        label: "시그니처 불일치",
        target: a("windows-filesystem", ["file-signature-mismatch"]),
      },
      {
        id: "fs-ntfs-records",
        label: "NTFS 레코드(런)",
        target: a("windows-filesystem", ["mft-record", "usn-record", "ntfs-logfile-transaction-candidate"]),
      },
      {
        id: "fs-strings",
        label: "문자열 후보(증거 아님)",
        target: a("windows-filesystem", ["full-path-string-candidate"]),
        nonEvidence: true,
      },
    ],
  },
  {
    id: "registry",
    label: "레지스트리",
    icon: "database",
    nodes: [
      {
        id: "reg-persistence",
        label: "자동 실행/지속성",
        target: a("windows-registry", ["registry-persistence-entry"]),
      },
      {
        id: "reg-activity",
        label: "사용자 활동(검색어·최근 문서·입력 경로)",
        target: a("windows-registry", ["registry-user-activity"]),
      },
      {
        id: "reg-shellbags",
        label: "ShellBags",
        target: a("windows-shellbags", ["shellbag-entry", "shellbag-hive-summary"]),
        typeLabels: { "shellbag-entry": "ShellBags 항목", "shellbag-hive-summary": "ShellBags 하이브 요약" },
      },
      {
        id: "reg-keytree",
        label: "키 트리",
        target: a("windows-registry", ["registry-key-tree-node"]),
        detail: true,
      },
      {
        id: "reg-recovery",
        label: "셀 복구",
        target: a("windows-registry", [
          "registry-deleted-cell-candidate",
          "registry-key-recovery-candidate",
          "registry-value-recovery-candidate",
        ]),
      },
      {
        id: "reg-strings",
        label: "문자열 후보(증거 아님)",
        target: a("windows-registry", ["registry-hive-string-candidate"]),
        nonEvidence: true,
      },
    ],
  },
  {
    id: "eventlog",
    label: "이벤트 로그",
    icon: "list",
    nodes: [
      { id: "evt-all", label: "전체 이벤트 로그(EVTX·ETL)", target: a("eventlog") },
      { id: "evt-events", label: "EVTX 이벤트", target: a("eventlog", ["eventlog-event"]) },
      { id: "evt-detections", label: "탐지 규칙 일치", target: a("eventlog", ["eventlog-detection"]) },
      { id: "evt-logon", label: "로그온 세션", target: a("eventlog", ["eventlog-logon-session"]) },
      {
        id: "evt-slack",
        label: "슬랙 복구 레코드",
        target: a("eventlog", ["eventlog-record-candidate"]),
      },
      { id: "evt-etl", label: "ETL 추적 파일", target: a("eventlog", ["etl-trace-file"]) },
      { id: "evt-firewall", label: "방화벽 로그", target: a("windows-system", ["firewall-log"]) },
    ],
  },
  {
    id: "web",
    label: "웹·브라우저",
    icon: "globe",
    nodes: [
      { id: "web-all", label: "브라우저 전체", target: a("browser") },
      {
        id: "web-history",
        label: "히스토리",
        target: a("browser", ["browser-history", "browser-visit"]),
        typeLabels: { "browser-history": "방문 URL", "browser-visit": "방문 기록" },
      },
      { id: "web-downloads", label: "다운로드", target: a("browser", ["browser-download"]) },
      {
        id: "web-downloads-macos",
        label: "다운로드(macOS)",
        target: a("macos-system", ["macos-browser-history-downloads"]),
      },
      { id: "web-search", label: "검색어", target: a("browser", ["browser-search"]) },
      { id: "web-cookies", label: "쿠키", target: a("browser", ["browser-cookie"]) },
      { id: "web-logins", label: "저장된 로그인", target: a("browser", ["browser-login"]) },
      {
        id: "web-autofill",
        label: "자동완성",
        target: a("browser", ["browser-autofill", "browser-credit-card", "browser-autofill-address"]),
        typeLabels: {
          "browser-autofill": "자동완성 항목",
          "browser-credit-card": "저장된 카드(메타데이터)",
          "browser-autofill-address": "저장된 주소",
        },
      },
      {
        id: "web-bookmarks",
        label: "북마크",
        target: a("browser", ["browser-bookmark", "browser-omnibox-shortcut", "browser-top-site"]),
        typeLabels: {
          "browser-bookmark": "북마크",
          "browser-omnibox-shortcut": "주소창 바로가기",
          "browser-top-site": "자주 가는 사이트",
        },
      },
      { id: "web-sessions", label: "세션", target: a("browser", ["browser-session-tab"]) },
      { id: "web-extensions", label: "확장", target: a("browser", ["browser-extension"]) },
      { id: "web-profile", label: "프로필 계정", target: a("browser", ["browser-profile-account"]) },
      {
        id: "web-anomaly",
        label: "이상/오류",
        target: a("browser", ["browser-acquisition-anomaly", "browser-parse-error"]),
        detail: true,
        typeLabels: { "browser-acquisition-anomaly": "취득 이상", "browser-parse-error": "파싱 오류" },
      },
      { id: "web-cache", label: "캐시(WebCache)", target: a("browser", ["webcachev01-ese-file"]) },
      {
        id: "web-cloud-sync",
        label: "클라우드 저장소 동기화",
        target: a("browser", ["desktop-cloud-sync-db", "desktop-cloud-sync-row-candidate"]),
      },
    ],
  },
  {
    id: "messaging",
    label: "메신저·메일",
    icon: "message",
    nodes: [
      // The Windows provider reads registry DeviceInfo / user-id traces, not the (encrypted) chat DB.
      { id: "msg-kakao", label: "카카오톡(Windows) 레지스트리 흔적", target: a("kakaotalk-windows") },
      { id: "msg-kakao-mac", label: "카카오톡(macOS)", target: a("kakaotalk-macos") },
      {
        id: "msg-mobile",
        label: "모바일 메시지",
        target: a("mobile-export", ["mobile-message", "mobile-chat-database"]),
      },
      { id: "msg-email", label: "이메일", target: a("email") },
      { id: "msg-docs", label: "문서/메일 색인", target: { collection: "docs" } },
    ],
  },
  {
    id: "cloud",
    label: "클라우드",
    icon: "cloud",
    nodes: [{ id: "cloud-export", label: "Takeout/iCloud/M365 내보내기", target: a("cloud-export") }],
  },
  {
    id: "media",
    label: "미디어·문서",
    icon: "image",
    nodes: [
      { id: "media-all", label: "미디어 전체", target: a("media-image") },
      {
        id: "media-images",
        label: "이미지",
        target: a("media-image", ["media-image", "media-image-unreadable"]),
        typeLabels: { "media-image": "이미지", "media-image-unreadable": "읽을 수 없는 이미지" },
      },
      { id: "media-video", label: "동영상", target: a("media-image", ["media-video"]) },
      { id: "media-audio", label: "오디오", target: a("media-image", ["media-audio"]) },
      { id: "media-ocr", label: "OCR 텍스트", target: run("ocr-batch") },
      {
        id: "media-doc-risk",
        label: "문서 메타데이터 위험",
        target: a("generic-documents", ["document-metadata-risk"]),
      },
      {
        id: "media-doc-lock",
        label: "문서 잠금 파일(편집자)",
        target: a("generic-documents", ["document-lock-owner"]),
      },
      { id: "media-documents", label: "문서 전체", target: a("generic-documents") },
      { id: "media-synthetic", label: "합성 미디어", target: a("synthetic-media") },
    ],
  },
  {
    id: "mobile",
    label: "모바일",
    icon: "smartphone",
    nodes: [
      {
        id: "mobile-ios",
        label: "iOS 백업",
        target: a("mobile-export", ["ios-backup-file", "ios-backup-metadata", "ios-backup-source"]),
      },
      { id: "mobile-android", label: "Android", target: a("android-apk") },
      { id: "mobile-all", label: "통합 뷰", target: a("mobile-export") },
    ],
  },
  {
    id: "devices",
    label: "연결 장치·원격",
    icon: "monitor",
    nodes: [
      {
        id: "dev-usb",
        label: "USB 설치 기록",
        target: a("windows-system", ["usb-setupapi-device-install-candidate"]),
      },
      {
        id: "dev-usb-registry",
        label: "USB·마운트 장치(레지스트리)",
        target: a("windows-registry", ["windows-usb-device", "windows-mounted-device"]),
        typeLabels: { "windows-usb-device": "USB 장치", "windows-mounted-device": "마운트된 장치" },
      },
      {
        id: "dev-usb-mounted",
        label: "USB·마운트 장치(reg 내보내기)",
        target: a("windows-os-account", ["windows-mounted-device", "windows-usb-device"]),
      },
      { id: "dev-rdp", label: "RDP", target: a("windows-remote-access") },
      {
        id: "dev-remote-tools",
        label: "원격 제어 도구",
        target: a("windows-remote-access", ["third-party-remote-control-artifact"]),
      },
      {
        id: "dev-remote-tools-system",
        label: "원격 제어 도구(시스템 흔적)",
        target: a("windows-system", ["third-party-remote-control-artifact"]),
      },
      { id: "dev-wifi", label: "Wi-Fi 프로필", target: a("windows-system", ["wifi-profile"]) },
    ],
  },
  {
    id: "anti-forensics",
    label: "안티 포렌식",
    icon: "shield",
    nodes: [
      {
        id: "af-ads",
        label: "ADS",
        target: a("windows-filesystem", ["ads-stream-candidate", "zone-identifier"]),
      },
      {
        id: "af-defender",
        label: "Defender 정책·로그",
        target: a("windows-system", ["defender-policy-artifact", "defender-support-log"]),
      },
    ],
  },
  {
    id: "incident",
    label: "침해사고",
    icon: "alert",
    nodes: [
      { id: "ir-webshell", label: "웹셸", target: a("windows-system", ["webshell-source-candidate"]) },
      { id: "ir-weblog", label: "웹 서버 로그", target: a("windows-system", ["web-server-log"]) },
      {
        id: "ir-persistence",
        label: "자동 실행/지속성",
        target: a("windows-registry", ["registry-persistence-entry"]),
        crossRef: true,
      },
      {
        id: "ir-detections",
        label: "이벤트 로그 탐지",
        target: a("eventlog", ["eventlog-detection"]),
        crossRef: true,
      },
      // Label from the indicators summary `display_label` ("지표 후보" while no rule applied).
      { id: "ir-ioc", label: "IOC 일치", target: { collection: "indicators" } },
      { id: "ir-cross-case", label: "교차 케이스 지표", target: run("cross-case") },
      {
        id: "ir-bits",
        label: "BITS 작업",
        target: a("windows-system", ["bits-qmgr-transfer-candidate", "bits-qmgr-sqlite-job-candidate"]),
      },
    ],
  },
  {
    id: "memory",
    label: "메모리",
    icon: "layers",
    nodes: [
      {
        id: "mem-volatility",
        label: "Volatility 정규화",
        target: a("memory-volatility", [
          "memory-process",
          "memory-network",
          "memory-cmdline",
          "memory-malfind",
          "memory-artifact",
        ]),
      },
      {
        id: "mem-dump",
        label: "메모리 덤프 지표",
        target: a("memory-volatility", ["memory-dump-indicators", "disk-memory-file-indicators"]),
      },
      // MDMP / WER crash dumps (stream header: time, PID, exception, modules), not Volatility.
      { id: "mem-crash", label: "크래시 덤프", target: a("memory-volatility", ["crash-dump-indicators"]) },
      {
        id: "mem-strings",
        label: "문자열 후보(증거 아님)",
        target: a("memory-volatility", ["process-string-candidate"]),
        nonEvidence: true,
      },
      { id: "mem-import", label: "메모리 분석 가져오기", target: run("memory-import") },
    ],
  },
  {
    id: "location",
    label: "위치·여행",
    icon: "map-pin",
    nodes: [
      { id: "loc-cloud", label: "클라우드 위치", target: a("cloud-export", ["cloud-location"]) },
      { id: "loc-mobile", label: "모바일 위치", target: a("mobile-export", ["mobile-location"]) },
    ],
  },
];

/** Selection key of a target (and of a route): collection | kind | types | ext. */
export function targetKey(
  target: Pick<DomainTarget, "collection" | "kind" | "types" | "ext"> & {
    category?: string;
    fileCategory?: string;
  },
): string {
  return [
    target.collection,
    target.collection === "files" ? (target.fileCategory ?? target.category ?? "") : "",
    target.kind ?? "",
    [...(target.types ?? [])].sort().join(","),
    [...(target.ext ?? [])].sort().join(","),
  ].join("|");
}
