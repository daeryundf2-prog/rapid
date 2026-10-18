/**
 * 통합 보기 tables (axiom-adoption §3.2): Korean labels, per-table columns, source-kind names, the
 * citation text and the grid route of an original row.
 */

import { filesInventoryCategory } from "../../api/collections";
import type { Route } from "../../router";
import { formatGridTime } from "../../utils/time";
import { nodeOfKind } from "../analysis/kinds";
import { familyById } from "../flags/catalog";
import type { DerivedRow, DerivedSample, DerivedSort, DerivedTableId } from "./api";

export const DERIVED_TABLE_LABELS: Record<DerivedTableId, string> = {
  people: "사람 식별자",
  devices: "장치 식별자",
  paths: "접근 경로",
  attachments: "첨부",
  credentials: "자격 증명/토큰",
  urls: "URL 분류",
};

/** One-sentence description under the pane title. */
export const DERIVED_TABLE_HINTS: Record<DerivedTableId, string> = {
  people: "계정·이메일·전화·이름처럼 사람을 가리키는 값을 모든 계열에서 모았습니다.",
  devices: "컴퓨터 이름·IP·MAC·볼륨 시리얼·USB 시리얼처럼 장치를 가리키는 값입니다.",
  paths: "실행·열람·바로 가기·셸백 등에 나온 파일·폴더 경로입니다(대소문자·구분자 정규화).",
  attachments: "메일·메신저 첨부 파일 이름입니다.",
  credentials: "암호·토큰 후보입니다. 원문은 저장하지 않고 가린 값·길이·SHA-256만 보여 줍니다.",
  urls: "방문·다운로드·북마크 등에 나온 URL을 호스트별로 모으고 분류했습니다.",
};

export const SEMANTIC_LABELS: Record<string, string> = {
  person: "사람",
  person_sender: "보낸 사람",
  person_recipient: "받는 사람",
  account: "계정",
  device: "장치",
  path: "경로",
  url: "URL",
  hash: "해시",
  geo: "좌표",
  search_term: "검색어",
  attachment: "첨부",
  credential: "자격 증명",
};

export const SORT_LABELS: Record<DerivedSort, string> = {
  count: "건수 많은 순",
  first_seen: "처음 본 시각 순",
  last_seen: "마지막 본 시각 순(최근 먼저)",
};

/** Korean names of row-source kinds (mirrors api/app/tree.py KIND_LABELS). */
const KIND_LABELS: Record<string, string> = {
  "windows-os-account": "OS 계정",
  eventlog: "EVTX",
  "windows-registry": "레지스트리 하이브",
  "windows-shellbags": "ShellBags",
  "windows-execution": "실행 흔적",
  "windows-prefetch": "Prefetch",
  "windows-search-index": "Windows 검색 색인",
  "recent-files": "최근 파일·LNK",
  "windows-remote-access": "원격 접속",
  browser: "브라우저",
  email: "이메일",
  "kakaotalk-windows": "카카오톡 (Windows)",
  "windows-messenger": "데스크톱 메신저 (Windows)",
  // R5 L1
  "email-clients": "메일 클라이언트 (Thunderbird·Windows 메일)",
  "media-player": "미디어 플레이어 재생 기록",
  "windows-phone-link": "휴대폰과 연결 (Phone Link)",
  "kakaotalk-macos": "카카오톡 (macOS)",
  "mobile-export": "모바일 내보내기",
  "cloud-export": "클라우드 내보내기",
  "cloud-sync": "클라우드 동기화 클라이언트",
  "android-apk": "Android APK",
  "media-image": "미디어 이미지",
  "synthetic-media": "합성 미디어",
  "generic-documents": "문서",
  "memory-volatility": "메모리 (Volatility)",
  "windows-filesystem": "파일시스템 기록",
  "windows-system": "Windows 시스템",
  "linux-system": "Linux 시스템",
  "macos-system": "macOS 시스템",
  "files:candidates": "파일(후보)",
  "files:inventory": "파일(인벤토리)",
};

export function kindLabel(kind: string): string {
  if (KIND_LABELS[kind]) return KIND_LABELS[kind] as string;
  if (kind.startsWith("analysis:")) return `분석 결과(${kind.slice("analysis:".length)})`;
  return kind;
}

export function familyLabel(family: string): string {
  return familyById(family)?.label ?? family;
}

/** Korean label of a catalogue column of `family` (the field a sample's value came from). */
export function fieldLabel(family: string, field: string): string {
  const def = familyById(family);
  const column = [...(def?.core_columns ?? []), ...(def?.aux_columns ?? [])].find((c) => c.key === field);
  return column?.label ?? field;
}

export interface DerivedColumn {
  id: string;
  header: string;
  /** CSS width (grid template). */
  width: string;
  text: (row: DerivedRow, tz: string) => string;
  mono?: boolean;
  numeric?: boolean;
}

const count = (row: DerivedRow) => row.count.toLocaleString("ko-KR");
const sources = (row: DerivedRow) =>
  Object.entries(row.families)
    .map(([family, n]) => `${familyLabel(family)} ${n.toLocaleString("ko-KR")}`)
    .join(" · ");
const time = (value: string | null, tz: string) => (value ? formatGridTime(value, tz) : "");

const COMMON_TAIL: DerivedColumn[] = [
  { id: "count", header: "건수", width: "84px", numeric: true, text: count },
  { id: "families", header: "출처 계열", width: "minmax(180px, 1.4fr)", text: sources },
  { id: "first", header: "처음 본 시각", width: "160px", text: (row, tz) => time(row.first_seen, tz) },
  { id: "last", header: "마지막 본 시각", width: "160px", text: (row, tz) => time(row.last_seen, tz) },
];

export const DERIVED_COLUMNS: Record<DerivedTableId, DerivedColumn[]> = {
  people: [
    { id: "value", header: "값", width: "minmax(160px, 1.4fr)", text: (row) => row.value },
    {
      id: "normalized",
      header: "정규화 값",
      width: "minmax(140px, 1fr)",
      mono: true,
      text: (row) => row.normalized,
    },
    {
      id: "semantic",
      header: "종류",
      width: "96px",
      text: (row) => SEMANTIC_LABELS[row.semantic] ?? row.semantic,
    },
    ...COMMON_TAIL,
  ],
  devices: [
    { id: "value", header: "값", width: "minmax(160px, 1.4fr)", mono: true, text: (row) => row.value },
    {
      id: "normalized",
      header: "정규화 값",
      width: "minmax(140px, 1fr)",
      mono: true,
      text: (row) => row.normalized,
    },
    ...COMMON_TAIL,
  ],
  paths: [
    { id: "value", header: "경로", width: "minmax(240px, 2fr)", mono: true, text: (row) => row.value },
    ...COMMON_TAIL,
  ],
  attachments: [
    { id: "value", header: "파일 이름", width: "minmax(200px, 1.6fr)", text: (row) => row.value },
    ...COMMON_TAIL,
  ],
  credentials: [
    { id: "value", header: "가린 값", width: "minmax(140px, 1fr)", mono: true, text: (row) => row.value },
    {
      id: "length",
      header: "길이",
      width: "64px",
      numeric: true,
      text: (row) => (typeof row.length === "number" ? String(row.length) : ""),
    },
    {
      id: "sha256",
      header: "SHA-256",
      width: "minmax(160px, 1fr)",
      mono: true,
      text: (row) => row.sha256 ?? row.normalized.replace(/^sha256:/, ""),
    },
    ...COMMON_TAIL,
  ],
  urls: [
    { id: "value", header: "호스트", width: "minmax(180px, 1.4fr)", mono: true, text: (row) => row.value },
    {
      id: "class",
      header: "분류",
      width: "150px",
      text: (row) => row.url_class_label ?? (row.url_class ? row.url_class : "분류 없음"),
    },
    ...COMMON_TAIL,
  ],
};

/** Accessible name of a table row: "<값>, <종류>, 건수 n, 출처 …". */
export function rowAccessibleName(table: DerivedTableId, row: DerivedRow, tz: string): string {
  const parts = DERIVED_COLUMNS[table]
    .map((column) => {
      const text = column.text(row, tz);
      return text ? `${column.header} ${text}` : "";
    })
    .filter(Boolean);
  return parts.join(", ");
}

/** Citation of a table value: `통합:<표>/<정규화 값>` + count and run. */
export function derivedCitation(
  table: DerivedTableId,
  row: Pick<DerivedRow, "normalized" | "count">,
  runId: string,
): string {
  return `통합:${DERIVED_TABLE_LABELS[table]}/${row.normalized}; 건수=${row.count}; 런=${runId}`;
}

/** The grid route that opens a sample's original row selected (row index = the JSONL record index). */
export function sampleRoute(runId: string, sample: DerivedSample): Route {
  if (sample.collection === "files") {
    const inventory = sample.scope === "inventory";
    return {
      runId,
      collection: "files",
      ...(inventory ? { category: filesInventoryCategory() } : {}),
      row: { collection: "files", locator: sample.locator },
    };
  }
  if (sample.collection === "analysis") {
    const analysisId = sample.analysis_id ?? "";
    const node = sample.analysis_kind ? nodeOfKind(sample.analysis_kind)?.id : undefined;
    return {
      runId,
      collection: "analysis",
      ...(node ? { kind: node } : {}),
      ...(analysisId ? { analysisId } : {}),
      row: { collection: "analysis", kind: analysisId || undefined, locator: sample.locator },
    };
  }
  return {
    runId,
    collection: "artifacts",
    kind: sample.kind,
    row: { collection: "artifacts", kind: sample.kind, locator: sample.locator },
  };
}

/** Short Korean description of a sample: "<계열> · <필드> · #<행> · <시각>". */
export function sampleLabel(sample: DerivedSample, tz: string): string {
  return [
    familyLabel(sample.family),
    fieldLabel(sample.family, sample.field),
    `${kindLabel(sample.kind)} #${sample.record_index.toLocaleString("ko-KR")}`,
    sample.time ? formatGridTime(sample.time, tz) : "",
  ]
    .filter(Boolean)
    .join(" · ");
}
