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
}

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

/** The 16 domains of console-ia §4 (증거 소스 is the evidence node built from the dashboard). */
export const DOMAINS: readonly DomainDef[] = [
  {
    id: "os",
    label: "운영체제·계정",
    icon: "cpu",
    nodes: [
      { id: "os-accounts", label: "사용자·그룹(SAM)", target: a("windows-os-account") },
      { id: "os-system", label: "시스템 정보(Windows)", target: a("windows-system") },
      { id: "os-linux", label: "Linux 시스템", target: a("linux-system") },
      { id: "os-macos", label: "macOS 시스템", target: a("macos-system") },
      { id: "os-installed", label: "설치 프로그램(Windows)", target: a("windows-system", ["uwp-package"]) },
      { id: "os-installed-linux", label: "설치 패키지(Linux)", target: a("linux-system", ["linux-package"]) },
      { id: "os-tasks", label: "작업 스케줄러", target: a("windows-system", ["task-scheduler-task"]) },
      { id: "os-tasks-linux", label: "cron(Linux)", target: a("linux-system", ["linux-cron-entry"]) },
      {
        id: "os-services",
        label: "서비스(Windows)",
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
      { id: "exec-prefetch", label: "Prefetch", target: a("windows-prefetch") },
      { id: "exec-all", label: "실행 흔적 전체", target: a("windows-execution") },
      {
        id: "exec-amcache",
        label: "Amcache/ShimCache",
        target: a("windows-execution", ["amcache-entry", "shimcache-entry"]),
      },
      {
        id: "exec-bam",
        label: "UserAssist/BAM",
        target: a("windows-execution", ["bam-entry", "userassist-schema-entry"]),
      },
      { id: "exec-lnk", label: "Jump List/LNK", target: a("recent-files") },
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
    ],
  },
  {
    id: "registry",
    label: "레지스트리",
    icon: "database",
    nodes: [
      { id: "reg-hives", label: "하이브", target: a("windows-registry") },
      { id: "reg-shellbags", label: "ShellBags", target: a("windows-shellbags") },
      {
        id: "reg-recovery",
        label: "셀 복구",
        target: a("windows-registry", [
          "registry-deleted-cell-candidate",
          "registry-key-recovery-candidate",
          "registry-value-recovery-candidate",
        ]),
      },
    ],
  },
  {
    id: "eventlog",
    label: "이벤트 로그",
    icon: "list",
    nodes: [
      { id: "evt-all", label: "EVTX 전체", target: a("eventlog") },
      { id: "evt-logon", label: "로그온 세션", target: a("eventlog", ["eventlog-logon-session"]) },
      { id: "evt-firewall", label: "방화벽 로그", target: a("windows-system", ["firewall-log"]) },
    ],
  },
  {
    id: "web",
    label: "웹·브라우저",
    icon: "globe",
    nodes: [
      { id: "web-all", label: "브라우저 전체", target: a("browser") },
      { id: "web-history", label: "히스토리", target: a("browser", ["browser-history"]) },
      { id: "web-downloads", label: "다운로드", target: a("browser", ["browser-history-downloads"]) },
      {
        id: "web-downloads-macos",
        label: "다운로드(macOS)",
        target: a("macos-system", ["macos-browser-history-downloads"]),
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
      { id: "msg-kakao", label: "카카오톡(Windows)", target: a("kakaotalk-windows") },
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
      { id: "media-images", label: "이미지 갤러리", target: a("media-image") },
      { id: "media-ocr", label: "OCR 텍스트", target: run("ocr-batch") },
      {
        id: "media-doc-risk",
        label: "문서 메타데이터 위험",
        target: a("generic-documents", ["document-metadata-risk"]),
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
        id: "dev-usb-mounted",
        label: "마운트된 장치",
        target: a("windows-os-account", ["windows-mounted-device"]),
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
      { id: "mem-volatility", label: "Volatility 정규화", target: a("memory-volatility") },
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
