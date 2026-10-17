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

import { filesInventoryCategory } from "../../api/collections";
import type { CollectionId, ColumnFilter } from "../../contracts/collection";
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
  /**
   * Files listing scope: "inventory" = every scanned file incl. the categories the scan did not
   * select (`GET /files?scope=inventory`, route `category=inventory[:<id>]`). Default: candidates.
   */
  fileScope?: "inventory";
  /** Promoted record-field columns opened with the node (route `cols=details.<key>`). */
  cols?: string[];
  /**
   * Column filters on the loaded rows (route `cf=`): a filtered view of its types, never their
   * primary node, and left out of the domain total.
   */
  cf?: ColumnFilter[];
  /** Count from this numeric field of the kind's `/tree` node instead of the per-type counts. */
  countField?: string;
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
  /**
   * Kind-wide catch-all ("… 전체"): reaches every type of the kind (also ones without a typed
   * node), but never adds to the domain total — the kind's types are spread over several domains.
   */
  catchAll?: boolean;
  /**
   * Sub-nodes (실행 흔적 › Amcache › 드라이버 …). A node with children is a group: its target is
   * the union of its evidence children; only the leaves are primary nodes and count in the total.
   */
  children?: DomainNodeDef[];
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
const inventory = (category?: string): DomainTarget => ({
  collection: "files",
  fileScope: "inventory",
  ...(category ? { fileCategory: category } : {}),
});
const derived = (table: string): DomainTarget => ({ collection: "derived", kind: table });
const run = (analysis: AnalysisNodeId): DomainTarget => ({
  collection: "analysis",
  kind: analysis,
  analysis,
});

/** EVTX recovered-record position detail (eventlog.py `evtx_record_id_position`). */
export const EVTX_RECORD_ID_POSITION = "evtx_record_id_position";
export const EVTX_STALE_BELOW_FIRST = "stale-below-first";

/** Amcache inventory types (execution.py AMCACHE_EXTENDED_SECTIONS, parser-quality r2) → Korean. */
export const AMCACHE_TYPE_LABELS: Readonly<Record<string, string>> = {
  "amcache-schema-row": "응용 프로그램 파일",
  "amcache-driver-binary": "드라이버 바이너리",
  "amcache-driver-package": "드라이버 패키지",
  "amcache-device-pnp": "PnP 장치",
  "amcache-device-container": "장치 컨테이너",
  "amcache-application-shortcut": "응용 프로그램 바로 가기",
  "amcache-device-census": "DeviceCensus 시스템 정보",
};
const AMCACHE_EVIDENCE_TYPES = Object.keys(AMCACHE_TYPE_LABELS);

/** Desktop messenger row types (artifacts/windows/messenger.py, plan r2-communication §3.1) → Korean. */
export const DESKTOP_MESSENGER_TYPE_LABELS: Readonly<Record<string, string>> = {
  "chat-message": "대화(메시지)",
  "chat-app-inventory": "앱 목록",
  "chat-contact": "연락처",
  "chat-parse-error": "처리 오류",
  "chat-attachment": "첨부 파일",
};
/** Evidence types of the group node (처리 오류 is a detail child, never in the total). */
const DESKTOP_MESSENGER_EVIDENCE_TYPES = [
  "chat-message",
  "chat-app-inventory",
  "chat-contact",
  "chat-attachment",
];

function pickLabels(labels: Readonly<Record<string, string>>, types: string[]): Record<string, string> {
  return Object.fromEntries(types.map((type) => [type, labels[type] ?? type]));
}

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
    // 통합 보기 (axiom-adoption §3.2): derived tables across every family (`/tree` node `derived:<table>`).
    id: "derived",
    label: "통합 보기",
    icon: "link",
    nodes: [
      { id: "derived-people", label: "사람 식별자", target: derived("people") },
      { id: "derived-devices", label: "장치 식별자", target: derived("devices") },
      { id: "derived-paths", label: "접근 경로", target: derived("paths") },
      { id: "derived-attachments", label: "첨부", target: derived("attachments") },
      { id: "derived-credentials", label: "자격 증명/토큰", target: derived("credentials") },
      { id: "derived-urls", label: "URL 분류", target: derived("urls") },
    ],
  },
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
      {
        id: "os-accounts-all",
        label: "OS 계정 전체(하이브·reg 내보내기)",
        target: a("windows-os-account"),
        catchAll: true,
      },
      {
        id: "os-profiles",
        label: "사용자 프로필",
        target: a("windows-os-account", ["windows-user-profile"]),
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
      {
        id: "os-notifications",
        label: "알림·활동 기록",
        target: a("windows-system", [
          "notification-database",
          "notification-row-candidate",
          "activities-cache-db",
          "activities-cache-row-candidate",
        ]),
        typeLabels: {
          "notification-database": "알림 DB",
          "notification-row-candidate": "알림 행 후보",
          "activities-cache-db": "활동 기록 DB(ActivitiesCache)",
          "activities-cache-row-candidate": "활동 기록 행 후보",
        },
      },
      {
        id: "os-thumbcache",
        label: "썸네일·아이콘 캐시",
        target: a("windows-system", [
          "thumbnail-cache-file",
          "icon-cache-file",
          "thumbnail-cache-entry-candidate",
          "icon-cache-entry-candidate",
          "thumbnail-cache-media-candidate",
          "icon-cache-media-candidate",
        ]),
        typeLabels: {
          "thumbnail-cache-file": "썸네일 캐시 파일",
          "icon-cache-file": "아이콘 캐시 파일",
          "thumbnail-cache-entry-candidate": "썸네일 캐시 항목 후보",
          "icon-cache-entry-candidate": "아이콘 캐시 항목 후보",
          "thumbnail-cache-media-candidate": "썸네일 캐시 이미지 후보",
          "icon-cache-media-candidate": "아이콘 캐시 이미지 후보",
        },
      },
      {
        // The server tree routes DeviceCensus to 운영체제 (api/app/tree.py); primary: 실행 흔적 › Amcache.
        id: "os-amcache-census",
        label: "Amcache 시스템 정보(DeviceCensus)",
        target: a("windows-execution", ["amcache-device-census"]),
        crossRef: true,
      },
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
        label: "Amcache",
        target: a("windows-execution", AMCACHE_EVIDENCE_TYPES),
        typeLabels: AMCACHE_TYPE_LABELS,
        children: [
          {
            id: "exec-amcache-files",
            label: "응용 프로그램 파일",
            target: a("windows-execution", ["amcache-schema-row"]),
          },
          {
            id: "exec-amcache-drivers",
            label: "드라이버",
            target: a("windows-execution", ["amcache-driver-binary", "amcache-driver-package"]),
            typeLabels: pickLabels(AMCACHE_TYPE_LABELS, ["amcache-driver-binary", "amcache-driver-package"]),
          },
          {
            id: "exec-amcache-devices",
            label: "장치",
            target: a("windows-execution", ["amcache-device-pnp", "amcache-device-container"]),
            typeLabels: pickLabels(AMCACHE_TYPE_LABELS, ["amcache-device-pnp", "amcache-device-container"]),
          },
          {
            id: "exec-amcache-shortcuts",
            label: "바로가기",
            target: a("windows-execution", ["amcache-application-shortcut"]),
          },
          {
            id: "exec-amcache-census",
            label: "센서스",
            target: a("windows-execution", ["amcache-device-census"]),
          },
          {
            id: "exec-amcache-hive",
            label: "하이브 파일",
            target: a("windows-execution", ["amcache-hive", "amcache-inventory-row"]),
            detail: true,
            typeLabels: { "amcache-hive": "Amcache 하이브", "amcache-inventory-row": "기타 인벤토리 행" },
          },
        ],
      },
      {
        id: "exec-shimcache",
        label: "ShimCache",
        target: a("windows-execution", ["shimcache-schema-entry"]),
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
      { id: "fs-inventory", label: "전체 파일(인벤토리)", target: inventory() },
      { id: "fs-documents", label: "문서", target: files("documents") },
      { id: "fs-images", label: "이미지", target: files("images") },
      { id: "fs-archives", label: "압축", target: files("archives") },
      { id: "fs-databases", label: "데이터베이스", target: files("databases") },
      { id: "fs-emails", label: "이메일 파일", target: files("emails") },
      // Files outside the selected scan categories: inventory rows only (no hash / content scan).
      { id: "fs-other", label: "기타 (스캔 제외)", target: inventory("other") },
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
      {
        id: "fs-artifacts-all",
        label: "파일시스템 아티팩트 전체",
        target: a("windows-filesystem"),
        catchAll: true,
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
      {
        id: "reg-hives",
        label: "하이브 파일·요약",
        target: a("windows-registry", ["registry-hive", "registry-hive-strings", "registry-summary"]),
        detail: true,
        typeLabels: {
          "registry-hive": "하이브 파일",
          "registry-hive-strings": "하이브 문자열 묶음",
          "registry-summary": "레지스트리 요약",
        },
      },
      { id: "reg-all", label: "레지스트리 전체", target: a("windows-registry"), catchAll: true },
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
      {
        // Recovered records whose id is below the first live record (ring-buffer residue the live
        // log already overwrote): eventlog.py `evtx_record_id_position = "stale-below-first"`.
        id: "evt-stale",
        label: "오래된 레코드(첫 레코드 이전)",
        target: {
          ...a("eventlog", ["eventlog-event", "eventlog-record-candidate"]),
          cols: [`details.${EVTX_RECORD_ID_POSITION}`],
          cf: [{ col: `f:${EVTX_RECORD_ID_POSITION}`, op: ":", value: EVTX_STALE_BELOW_FIRST }],
          countField: "stale_below_first_record_count",
        },
      },
      {
        id: "evt-files",
        label: "EVTX 파일·요약",
        target: a("eventlog", ["eventlog-file", "eventlog-summary"]),
        detail: true,
        typeLabels: { "eventlog-file": "EVTX 파일", "eventlog-summary": "이벤트 로그 요약" },
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
      // r2 M3: decoded Chromium Simple Cache / blockfile / CacheStorage entries and WebCache Content rows.
      { id: "web-cache-entries", label: "캐시 항목", target: a("browser", ["browser-cache-entry"]) },
      {
        // WebCacheV01 container rows reuse the browser row types; this is a filtered view (browser = ie-edge-legacy).
        id: "web-legacy-ie",
        label: "레거시 Edge/IE(WebCache)",
        target: {
          ...a("browser", ["browser-history", "browser-cache-entry", "browser-cookie", "browser-download"]),
          cols: ["details.browser", "details.webcache_container"],
          cf: [{ col: "f:browser", op: ":", value: "ie-edge-legacy" }],
        },
        typeLabels: {
          "browser-history": "방문 기록(History·MSHist)",
          "browser-cache-entry": "캐시(Content)",
          "browser-cookie": "쿠키(Cookies)",
          "browser-download": "다운로드(iedownload)",
        },
      },
      {
        id: "web-upload-candidates",
        label: "웹메일·웹하드 업로드 후보",
        target: a("browser", ["web-upload-candidate"]),
      },
      {
        id: "web-ai",
        label: "AI 서비스 사용",
        target: a("browser", ["browser-ai-usage", "browser-ai-conversation"]),
        typeLabels: { "browser-ai-usage": "AI 서비스 방문", "browser-ai-conversation": "AI 대화 후보" },
      },
      {
        id: "web-storage",
        label: "저장소 인벤토리",
        target: a("browser", [
          "browser-storage-inventory",
          "browser-cache-inventory",
          "browser-cookie-store-inventory",
          "browser-credential-store-inventory",
          "browser-extension-inventory",
          "browser-session-storage-inventory",
          "browser-sync-inventory",
        ]),
        detail: true,
      },
      {
        // One aggregate row per profile (history + downloads); the timeline uses the rows' own times.
        id: "web-history-downloads",
        label: "히스토리·다운로드 집계",
        target: a("browser", ["browser-history-downloads"]),
        detail: true,
      },
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
      {
        id: "msg-kakao-candidates",
        label: "카카오톡(Windows) 후보",
        target: a("kakaotalk-windows", [
          "kakaotalk-windows-user-id-candidate",
          "kakaotalk-windows-app-database",
          "kakaotalk-windows-source-candidate",
          "kakaotalk-windows-crypto-material-candidate",
        ]),
        typeLabels: {
          "kakaotalk-windows-user-id-candidate": "사용자 ID 후보",
          "kakaotalk-windows-app-database": "앱 DB",
          "kakaotalk-windows-source-candidate": "원본 후보",
          "kakaotalk-windows-crypto-material-candidate": "암호 자료 후보",
        },
      },
      {
        id: "msg-kakao-summary",
        label: "카카오톡(Windows) 상관 요약",
        target: a("kakaotalk-windows", ["kakaotalk-windows-correlation-summary"]),
        detail: true,
      },
      // r2 M2: decrypted chat rows (only with recovered key material), saved/cached pictures and
      // the per-profile decryption status ("복호 키 없음 — …" when the chat DB stays encrypted).
      {
        id: "msg-kakao-pictures",
        label: "카카오톡(Windows) 공유 사진",
        target: a("kakaotalk-windows", ["kakaotalk-shared-picture"]),
      },
      {
        id: "msg-kakao-messages",
        label: "카카오톡(Windows) 메시지",
        target: a("kakaotalk-windows", ["kakaotalk-message"]),
      },
      {
        id: "msg-kakao-inventory",
        label: "카카오톡(Windows) 복호 상태",
        target: a("kakaotalk-windows", ["kakaotalk-app-inventory"]),
        detail: true,
      },
      { id: "msg-kakao-mac", label: "카카오톡(macOS)", target: a("kakaotalk-macos") },
      // windows-messenger (plan r2-communication §3.1 M1): Teams·Slack·Discord·Telegram·WhatsApp·Skype·
      // LINE·WeChat·Zoom desktop apps. Children in Korean order; the 앱 column narrows to one app.
      {
        id: "msg-desktop",
        label: "데스크톱 메신저(Windows)",
        target: a("windows-messenger", DESKTOP_MESSENGER_EVIDENCE_TYPES),
        typeLabels: DESKTOP_MESSENGER_TYPE_LABELS,
        children: [
          {
            id: "msg-desktop-messages",
            label: "대화(메시지)",
            target: a("windows-messenger", ["chat-message"]),
          },
          {
            id: "msg-desktop-apps",
            label: "앱 목록",
            target: a("windows-messenger", ["chat-app-inventory"]),
          },
          { id: "msg-desktop-contacts", label: "연락처", target: a("windows-messenger", ["chat-contact"]) },
          {
            id: "msg-desktop-errors",
            label: "처리 오류",
            target: a("windows-messenger", ["chat-parse-error"]),
            detail: true,
          },
          {
            id: "msg-desktop-attachments",
            label: "첨부 파일",
            target: a("windows-messenger", ["chat-attachment"]),
          },
        ],
      },
      {
        id: "msg-mobile",
        label: "모바일 메시지",
        target: a("mobile-export", ["mobile-message", "mobile-chat-database"]),
      },
      { id: "msg-email", label: "이메일", target: a("email") },
      // r2 M2: Outlook PST/OST rows (pffexport/readpst) and ICS calendars.
      {
        id: "msg-email-attachments",
        label: "메일 첨부",
        target: a("email", ["email-attachment"]),
      },
      {
        id: "msg-email-containers",
        label: "메일 컨테이너(PST/OST)",
        target: a("email", ["email-container-inventory"]),
        detail: true,
      },
      { id: "msg-contacts", label: "연락처", target: a("email", ["contact"]) },
      { id: "msg-calendar", label: "일정(약속)", target: a("email", ["calendar-event"]) },
      { id: "msg-docs", label: "문서/메일 색인", target: { collection: "docs" } },
    ],
  },
  {
    id: "cloud",
    label: "클라우드",
    icon: "cloud",
    // Korean-sorted (localeCompare "ko": Hangul before Latin). Desktop sync clients: R2 M4, kind cloud-sync.
    nodes: [
      {
        id: "cloud-sync-accounts",
        label: "동기화 계정·폴더",
        target: a("cloud-sync", ["cloud-sync-account"]),
      },
      {
        id: "cloud-sync-events",
        label: "동기화 이벤트(업로드·삭제)",
        target: a("cloud-sync", ["cloud-sync-event"]),
      },
      {
        id: "cloud-sync-inventory",
        label: "동기화 클라이언트 인벤토리",
        target: a("cloud-sync", ["cloud-sync-inventory"]),
        detail: true,
      },
      {
        id: "cloud-sync-files",
        label: "동기화 파일",
        target: a("cloud-sync", ["cloud-sync-file"]),
      },
      { id: "cloud-export", label: "Takeout/iCloud/M365 내보내기", target: a("cloud-export") },
    ],
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
      {
        id: "media-archives",
        label: "압축 파일 목록",
        target: a("generic-documents", ["archive-file-inventory"]),
      },
      { id: "media-documents", label: "문서 전체", target: a("generic-documents") },
      { id: "media-synthetic", label: "합성 미디어", target: a("synthetic-media") },
      {
        id: "media-synthetic-status",
        label: "합성 미디어 스캔 상태",
        target: a("synthetic-media", [
          "synthetic-media-scan-status",
          "synthetic-media-scan-summary",
          "synthetic-media-scan-error",
        ]),
        detail: true,
        typeLabels: {
          "synthetic-media-scan-status": "스캔 상태",
          "synthetic-media-scan-summary": "스캔 요약",
          "synthetic-media-scan-error": "스캔 오류",
        },
      },
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
      {
        // The server tree routes these to 연결 장치 (api/app/tree.py); primary: 실행 흔적 › Amcache › 장치.
        id: "dev-amcache",
        label: "Amcache 장치(PnP·컨테이너)",
        target: a("windows-execution", ["amcache-device-pnp", "amcache-device-container"]),
        crossRef: true,
      },
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
      { id: "mem-all", label: "메모리 전체", target: a("memory-volatility"), catchAll: true },
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

/** Every node of the table, sub-nodes included (pre-order: a group before its children). */
export function flattenDomainNodes(nodes: readonly DomainNodeDef[]): DomainNodeDef[] {
  return nodes.flatMap((node) => [node, ...flattenDomainNodes(node.children ?? [])]);
}

/** Selection key of a target (and of a route): collection | kind | types | ext. */
export function targetKey(
  target: Pick<DomainTarget, "collection" | "kind" | "types" | "ext"> & {
    category?: string;
    fileCategory?: string;
    fileScope?: "inventory";
    /** 특이사항 filters (U-F4): part of the key only when set. */
    flags?: string[];
    flagGrade?: string;
  },
): string {
  const flagPart = `${target.flagGrade ? `|g=${target.flagGrade}` : ""}${
    target.flags?.length ? `|f=${[...target.flags].sort().join(",")}` : ""
  }`;
  const filesCategory = target.fileScope
    ? filesInventoryCategory(target.fileCategory)
    : (target.fileCategory ?? target.category ?? "");
  return (
    [
      target.collection,
      target.collection === "files" ? filesCategory : "",
      target.kind ?? "",
      [...(target.types ?? [])].sort().join(","),
      [...(target.ext ?? [])].sort().join(","),
    ].join("|") + flagPart
  );
}
