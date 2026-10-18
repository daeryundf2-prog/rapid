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
import {
  type CollectionId,
  type ColumnFilter,
  type RecordFieldFilters,
  type RecordFieldKey,
  recordFieldsKey,
} from "../../contracts/collection";
import type { IconName } from "../../icons";
import type { AnalysisNodeId } from "../analysis/kinds";
import { CHANNEL_FILTER_COLUMN, CHANNEL_GROUP_FILTER_COLUMN } from "../filters/filterModel";

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
  /**
   * Exact record-field filters the server applies (`browser=` / `service=`, route the same; r2
   * console fix M2). Counted from the kind's `/tree` `field_type_counts`; a filtered view of its
   * types, never their primary node, and left out of the domain total.
   */
  fields?: RecordFieldFilters;
  /**
   * Event-log channel group (`/tree` `artifacts:eventlog` `channel_groups[].id`): the count comes
   * from that group; the node opens the kind with the `evt_channel_group` filter (server
   * `channel_group=`).
   */
  channelGroup?: string;
  /** Analysis results node (collection "analysis"). */
  analysis?: AnalysisNodeId;
  /**
   * Sub-view of an analysis node (R3 §3.3, with a `cf` on `f:source` / `f:signature_kind` /
   * `f:recovery_method` / `f:in_use` the rows API applies exactly): count = sum of `<field>[key]`
   * of the newest completed job's summary (all keys when `keys` is empty).
   */
  analysisCount?: { field: "source_counts" | "source_in_use_counts" | "kind_counts"; keys: string[] };
  /** Why an analysis sub-view is empty while its job never ran (replaces the generic reason). */
  neverRanReason?: string;
  /** 파일 시스템 탐색기 (r4 §2.2): open the files listing with the folder tree at this folder (`""` = root). */
  dir?: string;
}

export interface DomainNodeDef {
  id: string;
  label: string;
  target: DomainTarget;
  icon?: IconName;
  /**
   * Tooltip (e.g. the 특이사항 rule a sub-view cross-links, cross-links between related nodes in
   * different domains); replaces the column-filter and record-field notes.
   */
  note?: string;
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
  /**
   * Shown first in its group (the messages of an app, then its pictures): `orderGroup` keeps
   * lead nodes in table order before the Korean-sorted rest.
   */
  lead?: boolean;
  /**
   * Children generated per value of a record field (`/tree` `field_type_counts`): one node per
   * value with rows of `types`, filtered server-side (`<field>=<value>`); values with 0 rows of
   * those types get no node (데스크톱 메신저 › 앱별 보기 › Slack …).
   */
  fieldChildren?: { field: RecordFieldKey; types: string[] };
}

/**
 * Order of a group's children (and a domain's nodes, r2 console fix m6): lead nodes in table
 * order, then evidence nodes, then detail (bulk / auxiliary) nodes, then views (column- or
 * field-filtered, per-value groups) — each part in Korean collation (`localeCompare("ko")`).
 */
export function orderGroup(nodes: readonly DomainNodeDef[]): DomainNodeDef[] {
  const rank = (node: DomainNodeDef) =>
    node.lead
      ? 0
      : node.fieldChildren || node.target.cf?.length || recordFieldsKey(node.target.fields)
        ? 3
        : node.detail || node.nonEvidence || node.catchAll
          ? 2
          : 1;
  const ko = new Intl.Collator("ko");
  return nodes
    .map((node, index) => ({ node, index }))
    .sort((a, b) => {
      const ra = rank(a.node);
      const rb = rank(b.node);
      if (ra !== rb) return ra - rb;
      if (ra === 0) return a.index - b.index;
      return ko.compare(a.node.label, b.node.label) || a.index - b.index;
    })
    .map((entry) => entry.node);
}

/**
 * Cross-link of the two cloud-sync sources (r2 console fix m10): the browser provider's sync-DB
 * rows (웹·브라우저) and the sync clients' account / file / event rows (클라우드).
 */
export const CLOUD_SYNC_CROSS_NOTE =
  "같은 질문의 다른 원본 — 웹·브라우저 › 클라우드 저장소 동기화(브라우저 측 DB)와 클라우드 › 동기화 계정·폴더/파일/이벤트(동기화 클라이언트)를 함께 보세요";

/**
 * Cross-link of the PCA sources (R3 O1): the PCA text files (실행 흔적) and the Compatibility
 * Assistant Store / Persisted registry values (레지스트리 › 프로그램 호환성 도우미, also listed under
 * 실행 흔적) answer the same question — "was this program run here".
 */
export const PCA_CROSS_NOTE =
  "같은 질문의 다른 원본 — 실행 흔적 › 프로그램 호환성 도우미(PCA 기록 파일: 실행·PCA 이벤트 시각)와 레지스트리 › 프로그램 호환성 도우미(Compatibility Assistant Store: 키 마지막 기록)를 함께 보세요";

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
/**
 * Event-log channel node: the server `channel_group=` filter (`cf=evt_channel_group:<id>`, group
 * ids of core/eventlog_channels.py) — exact on the server, so the node count is the page total.
 */
const channelNode = (group: string): DomainTarget => ({
  collection: "artifacts",
  kind: "eventlog",
  channelGroup: group,
  cf: [{ col: CHANNEL_GROUP_FILTER_COLUMN, op: ":", value: group }],
});
const run = (analysis: AnalysisNodeId): DomainTarget => ({
  collection: "analysis",
  kind: analysis,
  analysis,
});

/**
 * ntfs-meta rows of `details.source` values (R3 §3.3: mft+usn, timestamp-mismatch,
 * logfile-transaction). The grid picks the source's catalogue family columns itself
 * (grid/columns/analysis.ts `analysisFamily`): no promoted `cols`.
 */
const ntfsRows = (sources: string[]): DomainTarget => ({
  ...run("ntfs-meta"),
  cf: [{ col: "f:source", op: ":", value: sources.join(",") }],
  analysisCount: { field: "source_counts", keys: sources },
  neverRanReason: NTFS_META_NEVER_RAN,
});

/**
 * ntfs-meta `timestamp-mismatch` rows of in-use (`true`) or deleted (`false`) MFT records (server
 * `in_use=`): most real mismatch rows are deleted records, so the main node shows in-use ones.
 */
const ntfsMismatchRows = (inUse: boolean): DomainTarget => ({
  ...ntfsRows(["timestamp-mismatch"]),
  cf: [
    { col: "f:source", op: ":", value: "timestamp-mismatch" },
    { col: "f:in_use", op: ":", value: inUse ? "true" : "false" },
  ],
  analysisCount: {
    field: "source_in_use_counts",
    keys: [`timestamp-mismatch:${inUse ? "in-use" : "deleted"}`],
  },
});

/**
 * "복구됨(카빙)" of a family (R3 §3.3): carve rows `recovery_method=carved` of these signature kinds
 * (server `signature_kind=` / `recovery_method=`, core/carving.py CARVED_FAMILIES); all kinds when empty.
 */
export const carved = (kinds: string[]): DomainTarget => ({
  ...run("carve"),
  cf: [
    ...(kinds.length ? [{ col: "f:signature_kind", op: ":" as const, value: kinds.join(",") }] : []),
    { col: "f:recovery_method", op: ":", value: "carved" },
  ],
  analysisCount: { field: "kind_counts", keys: kinds },
  neverRanReason: CARVE_NEVER_RAN,
});

/** Label suffix of a family's carved sub-view. */
export const CARVED_LABEL = "복구됨(카빙)";
export const NTFS_META_NEVER_RAN =
  "NTFS 메타 분석 안 됨 — 처리 단계에서 NTFS 메타(MFT/USN)를 실행하면 결과가 여기에 나타납니다";
export const CARVE_NEVER_RAN =
  "카빙 분석 안 됨 — 처리 단계에서 카빙을 실행하면 복구된 파일이 여기에 나타납니다";
/** Signature kinds per family (core/carving.py CARVED_FAMILIES). */
export const CARVED_KINDS = {
  audio: ["wav", "mp3", "m4a"],
  video: ["mp4"],
  images: ["jpeg", "png", "gif"],
  documents: ["pdf", "docx", "xlsx", "pptx", "hwp", "hwpx"],
  archives: ["zip", "7z", "rar"],
  email: ["eml"],
  executables: ["pe"],
  eventlog: ["evtx"],
  databases: ["sqlite"],
} as const;

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

/** Registry network types (r3 O1 registry_depth.py) → Korean. */
export const REGISTRY_NETWORK_TYPE_LABELS: Readonly<Record<string, string>> = {
  "registry-network-share": "네트워크 공유·매핑 드라이브",
  "registry-network-profile": "네트워크 프로필(NetworkList)",
  "registry-wlan-profile": "무선 연결 이력(WLAN)",
};
const REGISTRY_NETWORK_TYPES = Object.keys(REGISTRY_NETWORK_TYPE_LABELS);

/** Desktop messenger row types (artifacts/windows/messenger.py, plan r2-communication §3.1) → Korean. */
export const DESKTOP_MESSENGER_TYPE_LABELS: Readonly<Record<string, string>> = {
  "chat-message": "메신저 대화",
  "chat-app-inventory": "메신저 앱 목록",
  "chat-contact": "메신저 연락처",
  "chat-parse-error": "메신저 처리 오류",
  "chat-attachment": "메신저 첨부",
};
/**
 * Evidence types of the group node: 앱 목록 (per-app inventory, r2 console fix m4) and 처리 오류
 * are detail children, never in the total.
 */
const DESKTOP_MESSENGER_EVIDENCE_TYPES = ["chat-message", "chat-contact", "chat-attachment"];

/** KakaoTalk (Windows) row types (kakaotalk_windows.py / kakaotalk_messages.py) → Korean. */
export const KAKAOTALK_WINDOWS_TYPE_LABELS: Readonly<Record<string, string>> = {
  "kakaotalk-message": "카카오톡(Windows) 메시지",
  "kakaotalk-shared-picture": "카카오톡(Windows) 공유 사진",
  "kakaotalk-windows-user-id-candidate": "카카오톡 사용자 ID 후보(레지스트리)",
  "kakaotalk-windows-crypto-material-candidate": "카카오톡 암호 자료 후보(DeviceInfo)",
  "kakaotalk-windows-app-database": "카카오톡 앱 DB",
  "kakaotalk-windows-source-candidate": "카카오톡 원본 후보",
  "kakaotalk-app-inventory": "카카오톡 복호 상태",
  "kakaotalk-windows-correlation-summary": "카카오톡 상관 요약",
};

/** Outlook PST/OST · .eml/.msg · ICS row types (email.py / email_pst.py) → Korean. */
export const EMAIL_TYPE_LABELS: Readonly<Record<string, string>> = {
  "email-message": "메일(메시지)",
  "email-attachment": "메일 첨부",
  contact: "메일 연락처(Outlook)",
  "calendar-event": "일정(Outlook·ICS)",
  "email-mailbox": "메일함 문자열(PST/OST)",
  "email-container-inventory": "메일 컨테이너(PST/OST)",
};
const EMAIL_EVIDENCE_TYPES = ["email-message", "email-attachment", "contact", "calendar-event"];

// --- R5 L1: communication and media apps ------------------------------------------------------
/** Desktop mail clients (artifacts/email_clients.py: Thunderbird, Windows Mail, Windows Live Mail) → Korean. */
export const MAIL_CLIENT_TYPE_LABELS: Readonly<Record<string, string>> = {
  "email-message": "메일 클라이언트 메일",
  "email-attachment": "메일 클라이언트 첨부",
  contact: "메일 클라이언트 연락처",
  "calendar-event": "메일 클라이언트 일정",
  "email-client-account": "메일 클라이언트 계정",
  "email-client-profile": "메일 클라이언트 프로필",
  "email-client-store": "메일 저장소(ESE) 후보",
  "email-client-parse-error": "메일 클라이언트 처리 오류",
};
/** Evidence types of the 메일 클라이언트 group (profile / store / error rows are detail children). */
const MAIL_CLIENT_EVIDENCE_TYPES = [
  "email-message",
  "email-attachment",
  "contact",
  "calendar-event",
  "email-client-account",
];
/** Phone Link / Your Phone (artifacts/windows/phone_link.py) → Korean. */
export const PHONE_LINK_TYPE_LABELS: Readonly<Record<string, string>> = {
  "phone-link-message": "휴대폰과 연결 문자",
  "phone-link-call": "휴대폰과 연결 통화",
  "phone-link-contact": "휴대폰과 연결 연락처",
  "phone-link-photo": "휴대폰과 연결 사진",
  "phone-link-device": "휴대폰과 연결 기기",
  "phone-link-parse-error": "휴대폰과 연결 처리 오류",
};
const PHONE_LINK_EVIDENCE_TYPES = [
  "phone-link-message",
  "phone-link-call",
  "phone-link-contact",
  "phone-link-photo",
];
/** Media player recent-play lists (artifacts/windows/media_players.py) → Korean. */
export const MEDIA_PLAYER_TYPE_LABELS: Readonly<Record<string, string>> = {
  "media-player-recent": "미디어 플레이어 재생 기록",
  "media-player-inventory": "미디어 플레이어 인벤토리",
  "media-player-parse-error": "미디어 플레이어 처리 오류",
};

/**
 * 이벤트 로그 › 채널별 › channel group nodes (core/eventlog_channels.py CHANNEL_GROUPS): Korean-sorted
 * (Hangul before Latin), then 기타 채널 and 채널 없음 last (the remainder buckets).
 */
export const EVENTLOG_CHANNEL_NODES: readonly DomainNodeDef[] = [
  // "(이벤트 채널)": the Windows Firewall EVTX channel, not 방화벽 로그 (pfirewall.log).
  { id: "evt-ch-firewall", label: "방화벽(이벤트 채널)", target: channelNode("firewall") },
  { id: "evt-ch-security", label: "보안", target: channelNode("security") },
  { id: "evt-ch-user-pnp", label: "사용자 PNP", target: channelNode("user-pnp") },
  // A view inside 시스템 (System rows of the Service Control Manager provider).
  { id: "evt-ch-services", label: "서비스(SCM)", target: channelNode("services") },
  { id: "evt-ch-storage", label: "스토리지", target: channelNode("storage") },
  { id: "evt-ch-system", label: "시스템", target: channelNode("system") },
  { id: "evt-ch-rdp", label: "원격 데스크톱", target: channelNode("rdp") },
  { id: "evt-ch-application", label: "응용 프로그램", target: channelNode("application") },
  { id: "evt-ch-task-scheduler", label: "작업 스케줄러", target: channelNode("task-scheduler") },
  { id: "evt-ch-office-alerts", label: "Office Alerts", target: channelNode("office-alerts") },
  { id: "evt-ch-powershell", label: "PowerShell", target: channelNode("powershell") },
  { id: "evt-ch-defender", label: "Windows Defender", target: channelNode("defender") },
  { id: "evt-ch-other", label: "기타 채널", target: channelNode("other") },
  // EVTX file/summary rows and records without a channel (detail: never in a total).
  { id: "evt-ch-none", label: "채널 없음", target: channelNode("none"), detail: true },
];

/** Channel groups that partition the event-log rows (서비스(SCM) is a view inside 시스템). */
export const EVENTLOG_PARTITION_GROUPS: readonly string[] = EVENTLOG_CHANNEL_NODES.map(
  (node) => node.target.channelGroup ?? "",
).filter((group) => group && group !== "services");

/**
 * 이벤트 로그 › 채널별: the group of the channel nodes. Its own view is every partition group (=
 * every event-log row) under the server group filter, so it is selected apart from 전체 이벤트 로그.
 */
export const EVENTLOG_CHANNELS_GROUP: DomainNodeDef = {
  id: "evt-channels",
  label: "채널별",
  target: {
    collection: "artifacts",
    kind: "eventlog",
    cf: [{ col: CHANNEL_GROUP_FILTER_COLUMN, op: ":", value: EVENTLOG_PARTITION_GROUPS.join("|") }],
  },
  note: "이벤트 로그 채널 그룹별 보기 — 하위 노드의 행 수는 /tree 채널 그룹 건수(서버 channel_group= 필터)입니다",
  children: [...EVENTLOG_CHANNEL_NODES],
};

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
        id: "exec-carved",
        label: `실행 파일(PE) ${CARVED_LABEL}`,
        target: carved([...CARVED_KINDS.executables]),
      },
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
      // r3 O1: PCA (text files: windows-execution; Compatibility Assistant\Store: windows-registry) and
      // FeatureUsage. One node per kind; Korean-sorted block.
      {
        id: "exec-feature-usage",
        label: "작업 표시줄 사용(FeatureUsage)",
        target: a("windows-registry", ["execution-feature-usage"]),
      },
      {
        id: "exec-pca-files",
        label: "프로그램 호환성 도우미(PCA 기록 파일)",
        target: a("windows-execution", ["execution-pca"]),
        note: PCA_CROSS_NOTE,
      },
      {
        id: "exec-pca-registry",
        label: "프로그램 호환성 도우미(PCA 레지스트리)",
        target: a("windows-registry", ["execution-pca"]),
        note: PCA_CROSS_NOTE,
      },
    ],
  },
  {
    id: "filesystem",
    label: "파일시스템",
    icon: "hard-drive",
    nodes: [
      {
        id: "fs-explorer",
        label: "폴더 탐색기",
        target: { collection: "files", dir: "" },
        lead: true,
        note: "볼륨 → 폴더 계층으로 내려가며 폴더의 파일을 목록에 표시합니다(←/→ 펼침, Enter 열기)",
      },
      { id: "fs-all", label: "전체 파일", target: { collection: "files" } },
      { id: "fs-inventory", label: "전체 파일(인벤토리)", target: inventory() },
      { id: "fs-documents", label: "문서", target: files("documents") },
      { id: "fs-images", label: "이미지", target: files("images") },
      { id: "fs-archives", label: "압축", target: files("archives") },
      { id: "fs-databases", label: "데이터베이스", target: files("databases") },
      { id: "fs-emails", label: "이메일 파일", target: files("emails") },
      // Files outside the selected scan categories: inventory rows only (no hash / content scan).
      { id: "fs-other", label: "기타 (스캔 제외)", target: inventory("other") },
      // MFT/USN records only (source=mft,usn): 타임스탬프 불일치 / $LogFile rows have their own nodes.
      { id: "fs-mft", label: "MFT/USN", target: ntfsRows(["mft", "usn"]) },
      // R3 §3.3: $SI/$FN disagreement rows of the ntfs-meta analysis (AXIOM "NTFS Timestamp Mismatch").
      {
        id: "fs-timestamp-mismatch",
        label: "타임스탬프 불일치",
        target: ntfsMismatchRows(true),
        note: "$STANDARD_INFORMATION과 $FILE_NAME 시각 불일치(사용 중인 MFT 레코드) — 특이사항 지표 ntfs.si_before_fn·ntfs.zero_subsecond와 같은 판정(MFT 행에 표시)",
      },
      {
        id: "fs-timestamp-mismatch-deleted",
        label: "타임스탬프 불일치(삭제된 레코드)",
        target: ntfsMismatchRows(false),
        detail: true,
        note: "삭제된(미사용) MFT 레코드의 $SI/$FN 시각 불일치 — 남은 레코드의 이전 값이라 실제 행 대부분이 여기에 속합니다",
      },
      {
        id: "fs-logfile",
        label: "$LogFile 트랜잭션",
        target: ntfsRows(["logfile-transaction"]),
      },
      {
        id: "fs-carve",
        label: "복구/카빙",
        target: run("carve"),
        note: "카빙 작업의 모든 후보 행 — 오탐으로 거부된 후보(복구 방법: 거부됨)도 포함합니다. 복구된 파일만 보려면 '복구됨(카빙) 전체(오탐 제외)'",
      },
      {
        id: "fs-carved",
        label: `${CARVED_LABEL} 전체(오탐 제외)`,
        target: carved([]),
        note: "카빙으로 복구된 파일만(복구 방법: 카빙) — 계열별 '복구됨(카빙)' 노드의 합. 거부된 후보까지 보려면 '복구/카빙'",
      },
      {
        id: "fs-databases-carved",
        label: `데이터베이스 ${CARVED_LABEL}`,
        target: carved([...CARVED_KINDS.databases]),
      },
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
        id: "reg-explorer",
        label: "레지스트리 탐색기(키·값)",
        target: { collection: "registry" },
        lead: true,
        note: "하이브 → 키 트리, 값 표(형식·데이터·디코딩), 키에서 나온 아티팩트 행으로 이동",
      },
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
      // r3 O1 registry depth (plan r3-os-depth §3.1): Korean-sorted block (Hangul before Latin).
      {
        id: "reg-default-browser",
        label: "기본 브라우저",
        target: a("windows-registry", ["registry-default-browser"]),
      },
      {
        id: "reg-network",
        label: "네트워크·공유·무선",
        target: a("windows-registry", REGISTRY_NETWORK_TYPES),
        typeLabels: REGISTRY_NETWORK_TYPE_LABELS,
        children: [
          {
            id: "reg-network-shares",
            label: "네트워크 공유·매핑 드라이브",
            target: a("windows-registry", ["registry-network-share"]),
          },
          {
            id: "reg-network-profiles",
            label: "네트워크 프로필(NetworkList)",
            target: a("windows-registry", ["registry-network-profile"]),
          },
          {
            id: "reg-network-wlan",
            label: "무선 연결 이력(WLAN)",
            target: a("windows-registry", ["registry-wlan-profile"]),
          },
        ],
      },
      {
        id: "reg-install-state",
        label: "설치 상태(App Paths·MSI)",
        target: a("windows-registry", ["registry-install-state"]),
      },
      {
        id: "reg-known-dlls",
        label: "알려진 DLL(KnownDLLs)",
        target: a("windows-registry", ["registry-known-dll"]),
      },
      {
        id: "reg-office-mru",
        label: "Office 최근 파일(MRU)",
        target: a("windows-registry", ["registry-office-mru"]),
      },
      {
        // Primary node: 실행 흔적 › 프로그램 호환성 도우미(PCA 레지스트리).
        id: "reg-pca",
        label: "프로그램 호환성 도우미(PCA)",
        target: a("windows-registry", ["execution-pca"]),
        crossRef: true,
        note: PCA_CROSS_NOTE,
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
      { id: "evt-carved", label: `EVTX ${CARVED_LABEL}`, target: carved([...CARVED_KINDS.eventlog]) },
      // 채널별 (plan r3-os-depth §3.2 O2): one group; counts from `/tree` `channel_groups`, rows
      // from the server `channel_group=` filter.
      EVENTLOG_CHANNELS_GROUP,
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
        // WebCacheV01 container rows reuse the browser row types: a server-filtered view
        // (`browser=ie-edge-legacy`), counted from `/tree` field_type_counts.browser.
        id: "web-legacy-ie",
        label: "레거시 Edge/IE(WebCache)",
        target: {
          ...a("browser", ["browser-history", "browser-cache-entry", "browser-cookie", "browser-download"]),
          cols: ["details.webcache_container"],
          fields: { browser: ["ie-edge-legacy"] },
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
        label: "클라우드 저장소 동기화(브라우저 측 DB)",
        target: a("browser", ["desktop-cloud-sync-db", "desktop-cloud-sync-row-candidate"]),
        note: CLOUD_SYNC_CROSS_NOTE,
      },
    ],
  },
  {
    id: "messaging",
    label: "메신저·메일",
    icon: "message",
    // One group per app (카카오톡 › …, 이메일 › …, 데스크톱 메신저 › …), every level in `orderGroup`
    // order (r2 console fix m6).
    nodes: orderGroup([
      {
        id: "msg-kakao",
        label: "카카오톡(Windows)",
        target: a("kakaotalk-windows", [
          "kakaotalk-message",
          "kakaotalk-shared-picture",
          "kakaotalk-windows-user-id-candidate",
          "kakaotalk-windows-crypto-material-candidate",
          "kakaotalk-windows-app-database",
          "kakaotalk-windows-source-candidate",
        ]),
        typeLabels: pickLabels(KAKAOTALK_WINDOWS_TYPE_LABELS, Object.keys(KAKAOTALK_WINDOWS_TYPE_LABELS)),
        children: orderGroup([
          // r2 M2: decrypted chat rows (only with recovered key material) and saved / cached pictures.
          {
            id: "msg-kakao-messages",
            label: "메시지",
            target: a("kakaotalk-windows", ["kakaotalk-message"]),
            lead: true,
          },
          {
            id: "msg-kakao-pictures",
            label: "공유 사진",
            target: a("kakaotalk-windows", ["kakaotalk-shared-picture"]),
            lead: true,
          },
          {
            // The registry DeviceInfo / user-id traces (NTUSER.DAT, reg exports) the key needs.
            id: "msg-kakao-registry",
            label: "레지스트리 흔적(사용자 ID·DeviceInfo)",
            target: a("kakaotalk-windows", [
              "kakaotalk-windows-user-id-candidate",
              "kakaotalk-windows-crypto-material-candidate",
            ]),
            typeLabels: pickLabels(KAKAOTALK_WINDOWS_TYPE_LABELS, [
              "kakaotalk-windows-user-id-candidate",
              "kakaotalk-windows-crypto-material-candidate",
            ]),
          },
          {
            id: "msg-kakao-candidates",
            label: "앱 DB·원본 후보",
            target: a("kakaotalk-windows", [
              "kakaotalk-windows-app-database",
              "kakaotalk-windows-source-candidate",
            ]),
            typeLabels: pickLabels(KAKAOTALK_WINDOWS_TYPE_LABELS, [
              "kakaotalk-windows-app-database",
              "kakaotalk-windows-source-candidate",
            ]),
          },
          {
            // Per-profile decryption status ("복호 키 없음 — …" when the chat DB stays encrypted).
            id: "msg-kakao-inventory",
            label: "복호 상태",
            target: a("kakaotalk-windows", ["kakaotalk-app-inventory"]),
            detail: true,
          },
          {
            id: "msg-kakao-summary",
            label: "상관 요약",
            target: a("kakaotalk-windows", ["kakaotalk-windows-correlation-summary"]),
            detail: true,
          },
        ]),
      },
      { id: "msg-kakao-mac", label: "카카오톡(macOS)", target: a("kakaotalk-macos") },
      { id: "msg-eml-carved", label: `이메일(EML) ${CARVED_LABEL}`, target: carved([...CARVED_KINDS.email]) },
      // windows-messenger (plan r2-communication §3.1 M1): Teams·Slack·Discord·Telegram·WhatsApp·Skype·
      // LINE·WeChat·Zoom desktop apps. 앱별 보기 lists one server-filtered node per app (`service=`).
      {
        id: "msg-desktop",
        label: "데스크톱 메신저(Windows)",
        target: a("windows-messenger", DESKTOP_MESSENGER_EVIDENCE_TYPES),
        typeLabels: DESKTOP_MESSENGER_TYPE_LABELS,
        children: orderGroup([
          {
            id: "msg-desktop-messages",
            label: "대화(메시지)",
            target: a("windows-messenger", ["chat-message"]),
            lead: true,
          },
          {
            id: "msg-desktop-apps",
            label: "앱 목록",
            target: a("windows-messenger", ["chat-app-inventory"]),
            detail: true,
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
          {
            id: "msg-desktop-by-app",
            label: "앱별 보기",
            target: a("windows-messenger", DESKTOP_MESSENGER_EVIDENCE_TYPES),
            typeLabels: pickLabels(DESKTOP_MESSENGER_TYPE_LABELS, DESKTOP_MESSENGER_EVIDENCE_TYPES),
            fieldChildren: { field: "service", types: DESKTOP_MESSENGER_EVIDENCE_TYPES },
          },
        ]),
      },
      {
        id: "msg-mobile",
        label: "모바일 메시지",
        target: a("mobile-export", ["mobile-message", "mobile-chat-database"]),
      },
      // r2 M2: Outlook PST/OST rows (pffexport/readpst, opt-in), .eml/.msg and ICS calendars.
      {
        id: "msg-email",
        label: "이메일",
        target: a("email", EMAIL_EVIDENCE_TYPES),
        // Every email type (the detail ones too): the 유형 filter and chips read them.
        typeLabels: EMAIL_TYPE_LABELS,
        children: orderGroup([
          {
            id: "msg-email-messages",
            label: "메일(메시지)",
            target: a("email", ["email-message"]),
            lead: true,
          },
          {
            // Takeout / M365 exports: the cloud-export kind's mail rows (primary: 클라우드 › 내보내기).
            id: "msg-email-cloud",
            label: "메일(클라우드 내보내기)",
            target: a("cloud-export", ["cloud-mail"]),
            crossRef: true,
          },
          {
            id: "msg-email-attachments",
            label: "메일 첨부",
            target: a("email", ["email-attachment"]),
          },
          { id: "msg-contacts", label: "메일 연락처(Outlook)", target: a("email", ["contact"]) },
          { id: "msg-calendar", label: "일정(Outlook·ICS)", target: a("email", ["calendar-event"]) },
          {
            id: "msg-email-containers",
            label: "메일 컨테이너(PST/OST)",
            target: a("email", ["email-container-inventory"]),
            detail: true,
          },
          {
            // Bounded string inventory of a PST/OST (no record structure): a detail node.
            id: "msg-email-mailbox",
            label: "메일함 문자열(PST/OST)",
            target: a("email", ["email-mailbox"]),
            detail: true,
          },
        ]),
      },
      { id: "msg-docs", label: "문서/메일 색인", target: { collection: "docs" } },
      // R5 L1: desktop mail clients (email-clients kind) and the Phone Link SMS rows (primary: 모바일).
      {
        id: "msg-mail-clients",
        // Sorts after 이메일 (its group names the shared email-message / contact / … types first).
        label: "이메일 클라이언트(Thunderbird·Windows 메일)",
        target: a("email-clients", MAIL_CLIENT_EVIDENCE_TYPES),
        typeLabels: MAIL_CLIENT_TYPE_LABELS,
        children: orderGroup([
          {
            id: "msg-mail-clients-messages",
            label: "메일(메시지)",
            target: a("email-clients", ["email-message"]),
            lead: true,
          },
          {
            id: "msg-mail-clients-attachments",
            label: "메일 첨부",
            target: a("email-clients", ["email-attachment"]),
          },
          {
            id: "msg-mail-clients-contacts",
            label: "연락처(주소록)",
            target: a("email-clients", ["contact"]),
          },
          { id: "msg-mail-clients-calendar", label: "일정", target: a("email-clients", ["calendar-event"]) },
          {
            id: "msg-mail-clients-accounts",
            label: "계정·서버",
            target: a("email-clients", ["email-client-account"]),
          },
          {
            id: "msg-mail-clients-profiles",
            label: "프로필·자격 증명 저장소(존재만)",
            target: a("email-clients", ["email-client-profile"]),
            detail: true,
          },
          {
            id: "msg-mail-clients-stores",
            label: "메일 저장소(ESE) 후보",
            target: a("email-clients", ["email-client-store"]),
            detail: true,
          },
          {
            id: "msg-mail-clients-errors",
            label: "처리 오류",
            target: a("email-clients", ["email-client-parse-error"]),
            detail: true,
          },
        ]),
      },
      {
        id: "msg-phone-link",
        label: "휴대폰과 연결 문자(Phone Link)",
        target: a("windows-phone-link", ["phone-link-message"]),
      },
    ]),
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
      {
        // The browser provider's own sync-DB rows (web domain primary): same question, other source.
        id: "cloud-sync-browser",
        label: "브라우저 측 동기화 DB",
        target: a("browser", ["desktop-cloud-sync-db", "desktop-cloud-sync-row-candidate"]),
        crossRef: true,
        note: CLOUD_SYNC_CROSS_NOTE,
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
      {
        id: "media-images-carved",
        label: `이미지 ${CARVED_LABEL}`,
        target: carved([...CARVED_KINDS.images]),
      },
      { id: "media-video-carved", label: `동영상 ${CARVED_LABEL}`, target: carved([...CARVED_KINDS.video]) },
      { id: "media-audio-carved", label: `오디오 ${CARVED_LABEL}`, target: carved([...CARVED_KINDS.audio]) },
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
      {
        id: "media-documents-carved",
        label: `문서 ${CARVED_LABEL}`,
        target: carved([...CARVED_KINDS.documents]),
      },
      {
        id: "media-archives-carved",
        label: `압축 ${CARVED_LABEL}`,
        target: carved([...CARVED_KINDS.archives]),
      },
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
      // R5 L1: media player recent-play lists (VLC, PotPlayer, GOM Player, KMPlayer).
      {
        id: "media-player-recent",
        label: "미디어 플레이어 재생 기록",
        target: a("media-player", ["media-player-recent"]),
      },
      {
        id: "media-player-inventory",
        label: "미디어 플레이어 인벤토리·오류",
        target: a("media-player", ["media-player-inventory", "media-player-parse-error"]),
        detail: true,
        typeLabels: pickLabels(MEDIA_PLAYER_TYPE_LABELS, [
          "media-player-inventory",
          "media-player-parse-error",
        ]),
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
      // R5 L1: Phone Link / Your Phone (휴대폰과 연결) rows synced to the PC.
      {
        id: "mobile-phone-link",
        label: "휴대폰과 연결(Phone Link)",
        target: a("windows-phone-link", PHONE_LINK_EVIDENCE_TYPES),
        typeLabels: PHONE_LINK_TYPE_LABELS,
        children: orderGroup([
          {
            // Primary node: 메신저·메일 › 휴대폰과 연결 문자 (artifact_domains routes phone-link-message there).
            id: "mobile-phone-link-messages",
            label: "문자(SMS·MMS)",
            target: a("windows-phone-link", ["phone-link-message"]),
            lead: true,
            crossRef: true,
          },
          {
            id: "mobile-phone-link-calls",
            label: "통화",
            target: a("windows-phone-link", ["phone-link-call"]),
          },
          {
            id: "mobile-phone-link-contacts",
            label: "연락처",
            target: a("windows-phone-link", ["phone-link-contact"]),
          },
          {
            id: "mobile-phone-link-photos",
            label: "사진",
            target: a("windows-phone-link", ["phone-link-photo"]),
          },
          {
            id: "mobile-phone-link-devices",
            label: "기기·처리 오류",
            target: a("windows-phone-link", ["phone-link-device", "phone-link-parse-error"]),
            detail: true,
            typeLabels: pickLabels(PHONE_LINK_TYPE_LABELS, ["phone-link-device", "phone-link-parse-error"]),
          },
        ]),
      },
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
      // r3 O1: BitLocker recovery key files (key value never stored: masked value, identifier, hashes).
      {
        id: "af-bitlocker-keys",
        label: "BitLocker 복구 키 파일",
        target: a("windows-system", ["bitlocker-recovery-key-file"]),
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

/** Analysis `details` keys whose column filters are server filters (and part of the selection key). */
const ANALYSIS_KEY_COLUMNS = new Set(["f:source", "f:signature_kind", "f:recovery_method", "f:in_use"]);

/**
 * Selection key of a target (and of a route): collection | kind | types | ext (+ the analysis
 * `details` server filters, so "타임스탬프 불일치" and "MFT/USN" are different selections).
 */
export function targetKey(
  target: Pick<DomainTarget, "collection" | "kind" | "types" | "ext"> & {
    category?: string;
    fileCategory?: string;
    fileScope?: "inventory";
    /** 특이사항 filters (U-F4): part of the key only when set. */
    flags?: string[];
    flagGrade?: string;
    /** Exact record-field filters (`browser=` / `service=`): part of the key only when set. */
    fields?: RecordFieldFilters;
    /** 파일 시스템 탐색기 folder / special node: the explorer view of files is its own node. */
    dir?: string;
    special?: string;
    /**
     * Column filters: part of the key only on event-log channel views (`evt_channel(_group)`) and
     * for the analysis `details` server filters (`f:source` / `f:signature_kind` / `f:recovery_method` / `f:in_use`).
     */
    cf?: readonly ColumnFilter[];
  },
): string {
  const fieldsPart = recordFieldsKey(target.fields);
  const cf = target.cf ?? [];
  // Only the channel filters themselves: a column filter typed on a channel view never changes
  // which node is selected.
  const channels = cf
    .filter((f) => f.col === CHANNEL_FILTER_COLUMN || f.col === CHANNEL_GROUP_FILTER_COLUMN)
    .map((f) => `${f.col}${f.op}${f.value}`);
  const flagPart = `${target.flagGrade ? `|g=${target.flagGrade}` : ""}${
    target.flags?.length ? `|f=${[...target.flags].sort().join(",")}` : ""
  }${fieldsPart ? `|r=${fieldsPart}` : ""}${channels.length ? `|ch=${channels.sort().join(",")}` : ""}`;
  const detailPart =
    target.collection === "analysis"
      ? (target.cf ?? [])
          .filter((filter) => ANALYSIS_KEY_COLUMNS.has(filter.col))
          .map((filter) => `|${filter.col}=${filter.value}`)
          .sort()
          .join("")
      : "";
  const fsExplorer = target.collection === "files" && (target.dir !== undefined || Boolean(target.special));
  const filesCategory = fsExplorer
    ? "|fs"
    : target.fileScope
      ? filesInventoryCategory(target.fileCategory)
      : (target.fileCategory ?? target.category ?? "");
  return (
    [
      target.collection,
      target.collection === "files" ? filesCategory : "",
      target.kind ?? "",
      [...(target.types ?? [])].sort().join(","),
      [...(target.ext ?? [])].sort().join(","),
    ].join("|") +
    flagPart +
    detailPart
  );
}
