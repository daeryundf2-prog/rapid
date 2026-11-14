/**
 * Value-label table (R7 stage 1 L3, console review C-D9 / C-W2 / C-R4; glossary "값 라벨"): the
 * Korean reading of every raw enum value the console shows — indicator type / scope / risk tag,
 * browser, output source, document kind, shell item kind, drive type, binary type, image format,
 * evidence nature … The raw value never reaches the visible text; it stays in the tooltip
 * ("원래 값: …"). A value with no reading is shown as written (a case value, not an id).
 *
 * Catalogue `value_labels` (per family column) win over this table; this one covers the values
 * that are the same under every family (`edge` is Edge wherever it appears).
 *
 * Semantics checked against the producers (rapidtriage/core/indicators.py classify_indicator /
 * indicator_risk_flags): `network` is the class of URL/domain indicators — "네트워크", not 내부망;
 * a private address is `private` → "사설망".
 */

import type { GridRow } from "../../contracts/collection";
import { setChipTypeLabel } from "../filters/filterModel";
import { artifactTypeLabel } from "../filters/typeLabels";
import { type CatalogFamily, familyForType, familyValueLabel } from "../flags/catalog";
import { koreanFieldLabel } from "../viewer/fieldSheets";
import type { CellValue, ColumnSpec } from "./types";

export type ValueDomain =
  | "indicatorType"
  | "indicatorScope"
  | "riskTag"
  | "browser"
  | "source"
  | "docKind"
  | "shellItemKind"
  | "driveType"
  | "binaryType"
  | "imageFormat"
  | "evidenceNature"
  | "dangerType"
  | "hiveRoot"
  | "provider"
  | "scoreSemantics";

export const VALUE_LABELS: Readonly<Record<ValueDomain, Readonly<Record<string, string>>>> = {
  /** Indicator `type` (indicators.py detect / IOC scanner hit types). */
  indicatorType: {
    ip: "IP",
    ipv4: "IP",
    ipv6: "IPv6",
    url: "URL",
    domain: "도메인",
    email: "이메일",
    md5: "MD5",
    sha1: "SHA-1",
    sha256: "SHA-256",
    hash: "해시",
    keyword: "키워드",
    path: "경로",
    hostname: "호스트 이름",
    mac: "MAC 주소",
    phone: "전화번호",
  },
  /** Indicator `classification` (classify_indicator, classify_ioc_scanner_hit). */
  indicatorScope: {
    global: "공인",
    private: "사설망",
    loopback: "루프백",
    reserved: "예약 대역",
    "non-global": "비공인",
    invalid: "잘못된 주소",
    hash: "해시",
    network: "네트워크",
    unknown: "미분류",
    "content-keyword-rule-hit": "본문 키워드 규칙 일치",
    "network-domain-rule-hit": "도메인 규칙 일치",
    "network-url-rule-hit": "URL 규칙 일치",
    "network-ip-rule-hit": "IP 규칙 일치",
    "file-hash-rule-hit": "파일 해시 규칙 일치",
    "local-rule-hit": "로컬 규칙 일치",
    "known-good": "알려진 정상",
  },
  /** Indicator `risk_flags` (indicator_risk_flags, ioc_scanner_risk_flags, TI enrichment). */
  riskTag: {
    "network-indicator": "네트워크 지표",
    "global-ip": "공인 IP",
    "url-ip-host": "IP 주소 호스트 URL",
    "cleartext-url": "평문 URL",
    "hash-indicator": "해시 지표",
    "ti-enriched": "위협 정보 보강",
    "local-ioc-rule-hit": "로컬 IOC 규칙 일치",
    "network-ioc-hit": "네트워크 IOC 일치",
    "file-hash-ioc-hit": "파일 해시 IOC 일치",
    "content-keyword-ioc-hit": "본문 키워드 IOC 일치",
    // R7 AI 사용: desktop AI app candidates (generic.py).
    "desktop-ai-app-artifact": "데스크톱 AI 앱 파일",
    "ai-service-usage": "AI 서비스 사용",
    "possible-ai-prompt-history": "AI 프롬프트 기록 가능성",
    "ai-message-table-candidate": "AI 메시지 표 후보",
  },
  /** Browser names as parsers write them. */
  browser: {
    edge: "Edge",
    "edge-legacy": "Edge(레거시)",
    chrome: "Chrome",
    chromium: "Chromium",
    firefox: "Firefox",
    whale: "네이버 웨일",
    brave: "Brave",
    opera: "Opera",
    vivaldi: "Vivaldi",
    safari: "Safari",
    ie: "Internet Explorer",
    "internet-explorer": "Internet Explorer",
    // AI service export files (browser.py build_ai_service_export_record).
    "service-export": "서비스 내보내기 파일",
    unknown: "알 수 없음",
  },
  /** Output a row / search hit / timeline event came from. */
  source: {
    documents: "문서",
    docs: "문서",
    "docs-index": "문서",
    artifacts: "아티팩트",
    files: "파일",
    timeline: "타임라인",
    indicators: "지표(IOC)",
    registry: "레지스트리",
    eventlog: "이벤트 로그",
    web: "웹",
    ocr: "OCR 텍스트",
    analysis: "분석",
    search: "전체 검색",
    path: "경로",
  },
  /** Document kind (docs index `kind`: the file format). */
  docKind: {
    txt: "텍스트(TXT)",
    log: "로그(LOG)",
    csv: "CSV",
    tsv: "TSV",
    // AI agent transcripts / configs (R7 AI 사용 runs).
    jsonl: "JSON Lines(JSONL)",
    yaml: "YAML",
    yml: "YAML",
    xml: "XML",
    json: "JSON",
    ini: "설정(INI)",
    html: "HTML",
    htm: "HTML",
    md: "마크다운",
    pdf: "PDF",
    docx: "Word(DOCX)",
    doc: "Word(DOC)",
    xlsx: "Excel(XLSX)",
    xls: "Excel(XLS)",
    pptx: "PowerPoint(PPTX)",
    ppt: "PowerPoint(PPT)",
    hwp: "한글(HWP)",
    hwpx: "한글(HWPX)",
    rtf: "RTF",
    eml: "메일(EML)",
    msg: "메일(MSG)",
    odt: "ODT",
    zip: "ZIP",
  },
  /** ShellBags / LNK shell item kind. */
  shellItemKind: {
    root: "루트",
    "root-key": "루트 키",
    directory: "폴더",
    file: "파일",
    drive: "드라이브",
    volume: "볼륨",
    network: "네트워크 위치",
    "control-panel": "제어판",
    "users-property-view": "사용자 속성 보기",
    uri: "URI",
    "zip-folder": "ZIP 폴더",
    "mtp-device": "MTP 장치",
    unknown: "알 수 없음",
  },
  /** LNK `drive_type_name`. */
  driveType: {
    fixed: "고정 디스크",
    removable: "이동식",
    remote: "네트워크",
    cdrom: "CD-ROM",
    ramdisk: "RAM 디스크",
    "no-root-dir": "루트 없음",
    unknown: "알 수 없음",
  },
  /** Amcache / PE `binary_type`. */
  binaryType: {
    pe32_i386: "PE32(x86)",
    pe64_amd64: "PE64(x64)",
    pe32_clr_il: "PE32(.NET IL)",
    // AnyCPU .NET built with "Prefer 32-bit" (Amcache BinaryType; 16 rows on run-subset10, r7 S1).
    pe32_clr_il_prefer32: "PE32(.NET IL, 32비트 우선)",
    pe32_clr_32: "PE32(.NET x86)",
    pe64_arm64: "PE64(ARM64)",
    pe64_clr_64: "PE64(.NET x64)",
    unknown: "알 수 없음",
  },
  /** Image `content_format`. */
  imageFormat: {
    png: "PNG",
    jpeg: "JPEG",
    jpg: "JPEG",
    gif: "GIF",
    bmp: "BMP",
    webp: "WebP",
    heic: "HEIC",
    tiff: "TIFF",
    ico: "ICO",
    svg: "SVG",
    unknown: "알 수 없음",
  },
  /** `evidence_nature` (what kind of trace a row is). */
  evidenceNature: {
    "registry-string-trace": "레지스트리 문자열 흔적",
    "string-candidate": "문자열 후보",
    "file-trace": "파일 흔적",
    "database-row": "DB 행",
    "log-line": "로그 줄",
    "metadata-only": "메타데이터만",
  },
  /** Chrome / Edge download `danger_type`. */
  dangerType: {
    NOT_DANGEROUS: "위험 없음",
    DANGEROUS_FILE: "위험 파일 형식",
    DANGEROUS_URL: "위험 URL",
    DANGEROUS_CONTENT: "위험 콘텐츠",
    MAYBE_DANGEROUS_CONTENT: "위험 가능 콘텐츠",
    UNCOMMON_CONTENT: "드문 콘텐츠",
    USER_VALIDATED: "사용자가 허용함",
    DANGEROUS_HOST: "위험 호스트",
    POTENTIALLY_UNWANTED: "원치 않는 프로그램 가능성",
    ALLOWLISTED_BY_POLICY: "정책 허용",
    ASYNC_SCANNING: "검사 중",
    BLOCKED_PASSWORD_PROTECTED: "암호 보호로 차단",
    BLOCKED_TOO_LARGE: "크기 초과로 차단",
    SENSITIVE_CONTENT_WARNING: "민감 콘텐츠 경고",
    SENSITIVE_CONTENT_BLOCK: "민감 콘텐츠 차단",
    DEEP_SCANNED_SAFE: "정밀 검사 안전",
    DEEP_SCANNED_OPENED_DANGEROUS: "위험 확인 후 열림",
    PROMPT_FOR_SCANNING: "검사 요청",
    BLOCKED_UNSUPPORTED_FILETYPE: "지원 안 되는 형식으로 차단",
    DANGEROUS_ACCOUNT_COMPROMISE: "계정 탈취 위험",
  },
  /** Registry hive roots (`hive_hint`): shown in their usual short form. */
  hiveRoot: {
    HKEY_CURRENT_USER: "HKCU",
    HKEY_LOCAL_MACHINE: "HKLM",
    HKEY_USERS: "HKU",
    HKEY_CLASSES_ROOT: "HKCR",
    HKEY_CURRENT_CONFIG: "HKCC",
  },
  /** Row `provider` (the collector that wrote the row). */
  provider: {
    "windows-system-artifacts": "Windows 시스템 수집기",
    "generic-documents": "문서 수집기",
    "windows-os-account": "OS 계정 수집기",
    "windows-registry-artifacts": "레지스트리 수집기",
    "windows-execution-artifacts": "실행 흔적 수집기",
    "browser-artifacts": "브라우저 수집기",
    "eventlog-artifacts": "이벤트 로그 수집기",
    // R7 AI 사용 (artifacts/ai_agents AI_PROVIDER_NAME).
    "ai-agents": "AI 사용 기록 수집기",
  },
  /** Synthetic-media `score_semantics`. */
  scoreSemantics: {
    "prioritization-score-not-truth-label": "검토 우선순위 점수(진위 판정 아님)",
  },
};

/** Catalogue column keys (and grid field ids) whose values read through one domain. */
export const KEY_DOMAINS: Readonly<Record<string, ValueDomain>> = {
  browser: "browser",
  browser_name: "browser",
  drive_type_name: "driveType",
  drive_type: "driveType",
  item_kind: "shellItemKind",
  shell_item_kind: "shellItemKind",
  binary_type: "binaryType",
  content_format: "imageFormat",
  image_format: "imageFormat",
  evidence_nature: "evidenceNature",
  danger_type: "dangerType",
  hive_hint: "hiveRoot",
  score_semantics: "scoreSemantics",
  risk_flags: "riskTag",
  riskFlags: "riskTag",
};

/** Korean reading of `raw` in `domain`, or undefined when the table has none. */
export function valueReading(domain: ValueDomain, raw: unknown): string | undefined {
  if (typeof raw !== "string" || !raw) return undefined;
  const table = VALUE_LABELS[domain];
  return table[raw] ?? table[raw.toLowerCase()];
}

/** Display text of `raw` in `domain`: the reading, else the value as written. */
export function valueLabel(domain: ValueDomain, raw: unknown): string {
  if (raw === null || raw === undefined) return "";
  return valueReading(domain, raw) ?? String(raw);
}

/** A comma-separated (or array) list read item by item: "network-indicator, cleartext-url" → "네트워크 지표, 평문 URL". */
export function valueListLabel(domain: ValueDomain, raw: unknown): string {
  const items = Array.isArray(raw)
    ? raw.map(String)
    : typeof raw === "string"
      ? raw
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean)
      : [];
  return items.map((item) => valueLabel(domain, item)).join(", ");
}

/** Reading of a value under record key `key` (KEY_DOMAINS), undefined when the key has no domain. */
export function keyValueReading(key: string, raw: unknown): string | undefined {
  const domain = KEY_DOMAINS[key];
  if (!domain) return undefined;
  if (domain === "riskTag" && typeof raw === "string" && raw.includes(",")) {
    const label = valueListLabel(domain, raw);
    return label !== raw ? label : undefined;
  }
  return valueReading(domain, raw);
}

/** "원래 값: global" tooltip when the shown text differs from the raw value. */
export function rawTooltip(raw: CellValue, shown: string): string {
  const text = raw === null || raw === undefined ? "" : String(raw);
  return text && text !== shown ? `${shown} (원래 값: ${text})` : shown;
}

/**
 * Column `format` + `tooltip` for a cell that shows one value of `domain` (`list` = comma list):
 * `col.field(id, header, width, presets, pick, labelledCell("indicatorScope", pick))`.
 */
export function labelledCell(
  domain: ValueDomain,
  pick: (row: GridRow) => CellValue,
  list = false,
): Pick<ColumnSpec, "format" | "tooltip"> {
  const shown = (row: GridRow) => (list ? valueListLabel(domain, pick(row)) : valueLabel(domain, pick(row)));
  return {
    format: shown,
    tooltip: (row) => rawTooltip(pick(row), shown(row)),
  };
}

/** Korean name of an artifact type: the tree's node name, else its family's name, else the id. */
export function typeDisplayLabel(type: string | null | undefined): string {
  if (!type) return "";
  return artifactTypeLabel(type) ?? familyForType(type)?.label ?? type;
}

/**
 * Korean name of a flag evidence field (특이사항 근거, C-R4): the family's catalogue column label
 * for that key (or alias), else the record-key label; null when there is none (raw key shown mono).
 */
export function evidenceFieldLabel(family: CatalogFamily | undefined, key: string): string | null {
  const def = family
    ? [...family.core_columns, ...family.aux_columns].find(
        (column) => column.key === key || (column.aliases ?? []).includes(key),
      )
    : undefined;
  if (def?.label) return def.label;
  return koreanFieldLabel(key);
}

/** Display text of a flag evidence value: catalogue `value_labels`, the shared table, else as written. */
export function evidenceValueText(familyId: string | undefined, key: string, value: string): string {
  return familyValueLabel(familyId, key, value) ?? keyValueReading(key, value) ?? value;
}

// The 유형 condition chips read the same Korean type names (filterModel cannot import the tree).
setChipTypeLabel(artifactTypeLabel);
