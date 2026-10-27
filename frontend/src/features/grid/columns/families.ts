/**
 * Family columns (viewer-families plan U-F3): the catalogue (`GET /api/meta/families`, bundled
 * fallback until it loads) gives each artifact family its core columns in examiner order and its
 * auxiliary columns ("카탈로그 보조 열"). Time columns carry their timestamp kind (`ts_kind`) as a
 * chip in the cell ($SI/$FN, LNK source/target, key LastWrite vs value time …).
 *
 * KIND_COLUMNS (artifacts.ts) stays the fallback for kinds the catalogue does not claim exactly
 * once (mixed kinds such as windows-system).
 */

import { createElement } from "react";
import type { GridRow } from "../../../contracts/collection";
import { clipValue, flatValue } from "../../../utils/flatValue";
import { formatGridTime } from "../../../utils/time";
import { timestampKindLabel } from "../../../utils/timeKinds";
import { deriveColumn, missingText } from "../../derived/derivedFields";
import { artifactTypeLabel } from "../../filters/typeLabels";
import {
  type CatalogColumn,
  type CatalogFamily,
  columnValueLabel,
  familyForType,
  getCatalog,
} from "../../flags/catalog";
import { FlagCell } from "../../flags/FlagCell";
import { flagSortValue, flagsAccessibleName, rowFlags } from "../../flags/flags";
import { eventLevelLabel, logonTypeLabel, severityLabel } from "../../viewer/fieldFormat";
import { EVENT_DATA_KEYS } from "../../viewer/fieldSheets";
import type { ColumnSpec } from "../types";
import { keyValueReading } from "../valueLabels";
import { currentTimezone, formatBytes, isRecord, TIME_COLUMN_MIN } from "./common";

/** Korean reading of a timestamp kind (chip tooltip / accessible text). */
export const TS_KIND_LABELS: Record<string, string> = {
  // backend catalogue (rapidtriage/core/triage_rules/catalog/*.yaml)
  logged: "기록 시각",
  "account-expires": "계정 만료",
  "download-start": "다운로드 시작",
  "download-end": "다운로드 완료",
  "cache-response": "캐시 응답",
  "cache-request": "캐시 요청",
  "first-install": "최초 설치",
  "last-accessed": "마지막 접근",
  "last-connected": "마지막 연결",
  "last-failed-logon": "마지막 로그온 실패",
  "last-logon": "마지막 로그온",
  "last-removal": "마지막 분리",
  "last-updated": "마지막 갱신",
  "last-used": "마지막 사용",
  "last-visited": "마지막 방문",
  "last-written": "키 마지막 기록",
  "logon-start": "로그온 시작",
  "logon-end": "로그오프",
  "mft-modified": "MFT 변경",
  "password-last-set": "암호 변경",
  "target-accessed": "대상 접근",
  "target-created": "대상 생성",
  "target-modified": "대상 수정",
  // ShimCache: the file's own LastModified time, never a run time (C8).
  "file-last-modified": "파일 수정(실행 아님)",
  event: "이벤트 시각",
  created: "생성",
  modified: "수정",
  accessed: "접근",
  mft: "MFT 변경",
  last: "마지막",
  first: "최초",
  run: "실행",
  installed: "설치",
  registered: "등록",
  logon: "로그온",
  password: "암호 변경",
  account: "계정 생성",
  sent: "발신",
  server: "서버 시각",
  visited: "방문",
  download: "다운로드",
  upload: "업로드",
  expires: "만료",
  captured: "촬영",
  taken: "촬영",
  digitized: "디지털화",
  edited: "편집",
  gps: "GPS 시각",
  target: "대상 파일 시각",
  // r2 M2: calendar-event start / end
  start: "시작",
  end: "종료",
  // R5 L2: StartupApproved disabled time
  disabled: "사용 안 함 설정",
  // older spellings (families mock / earlier servers)
  first_seen: "최초 확인",
  last_run: "최근 실행",
  mft_changed: "MFT 변경",
  deleted: "삭제",
  key_lastwrite: "키 마지막 기록",
  received: "수신",
  read: "읽음",
  visit: "방문",
  capture: "촬영",
  printed: "인쇄",
  last_logon: "마지막 로그온",
  last_connect: "마지막 연결",
  first_install: "최초 설치",
  last_removal: "마지막 분리",
  download_end: "다운로드 완료",
};

/** Korean name of a timestamp kind; an unknown id reads "시각 종류: <id>" rather than bare English. */
export function tsKindLabel(kind: string): string {
  const own = TS_KIND_LABELS[kind] ?? TS_KIND_LABELS[kind.replace(/-/g, "_")];
  if (own) return own;
  // The parsers' / timeline's kinds (cloud-upload, cache-created, saved …): utils/timeKinds.
  const shared = timestampKindLabel(kind);
  return shared && shared !== kind ? shared : `시각 종류: ${kind}`;
}

/**
 * Timestamp kind of a row's `timestamp_label` (parsers that write a label but no
 * `timestamp_kind`: PCA, registry depth). PCA's PcaAppLaunchDic is a run time, PcaGeneralDb an
 * event, the Compatibility Assistant Store / Persisted key a key LastWrite.
 */
export const TIMESTAMP_LABEL_KINDS: Readonly<Record<string, string>> = {
  last_run: "run",
  run: "run",
  pca_event: "pca-event",
  last_written: "last-written",
  last_written_mru_head: "last-written",
  // ShimCache rows (`timestamp_label: file_last_modified`): the file's LastModified, not a run (C8).
  file_last_modified: "file-last-modified",
  key_last_written: "last-written",
  last_connected: "last-connected",
  first_connected: "first-connected",
  last_opened: "last-opened",
  created: "created",
  modified: "modified",
  accessed: "accessed",
};

/** The row's own timestamp kind: `timestamp_kind`, else its `timestamp_label` read as a kind. */
export function rowTimestampKind(details: Record<string, unknown>): string | undefined {
  const own = details.timestamp_kind;
  if (typeof own === "string" && own) return own;
  const label = details.timestamp_label;
  if (typeof label !== "string" || !label) return undefined;
  return TIMESTAMP_LABEL_KINDS[label] ?? TIMESTAMP_LABEL_KINDS[label.replace(/-/g, "_")];
}

/**
 * The timestamp kind of a time cell: the row's own `timestamp_kind` (or `timestamp_label`) for the
 * generic `timestamp` column (a cache entry falls back from the response to the created /
 * last-used time, a cloud event is an upload or a delete, a PCA row is a run or a PCA event …),
 * else the catalogue column's `ts_kind`.
 */
export function cellTsKind(
  def: CatalogColumn,
  details: Record<string, unknown>,
  from: string,
): string | undefined {
  if (def.format !== "time") return undefined;
  if (from === "timestamp" || def.key === "timestamp") {
    const own = rowTimestampKind(details);
    if (own) return own;
  }
  return def.ts_kind;
}

/** Column id of a catalogue column (same `d:` space as KIND_COLUMNS: promoted keys dedupe on it). */
export function familyColumnId(key: string): string {
  return `d:${key}`;
}

function detailsOf(row: { fields: Record<string, unknown> }): Record<string, unknown> {
  return isRecord(row.fields.details) ? row.fields.details : {};
}

function present(value: unknown): boolean {
  return (
    value !== undefined && value !== null && value !== "" && !(Array.isArray(value) && value.length === 0)
  );
}

/**
 * One candidate key: a top-level key, `event_data.X` (any EVTX EventData container) or a dotted
 * path; a numeric part indexes a list (`last_run_times.0` = Prefetch's most recent run).
 */
export function readKey(details: Record<string, unknown>, key: string): unknown {
  if (!key.includes(".")) return details[key];
  const [head, ...rest] = key.split(".");
  const containers = head === "event_data" ? EVENT_DATA_KEYS : [head as string];
  for (const name of containers) {
    let value: unknown = details[name];
    for (const part of rest) {
      if (Array.isArray(value) && /^\d+$/.test(part)) value = value[Number(part)];
      else value = isRecord(value) ? value[part] : undefined;
    }
    if (present(value)) return value;
  }
  return undefined;
}

/** First present value among the column's key and aliases, with the key it came from. */
export function readColumn(
  details: Record<string, unknown>,
  def: Pick<CatalogColumn, "key" | "aliases">,
): { value: unknown; from: string } | null {
  for (const key of [def.key, ...(def.aliases ?? [])]) {
    const value = readKey(details, key);
    if (present(value)) return { value, from: key };
  }
  return null;
}

/**
 * Numeric-only ids in a person / conversation column (KakaoTalk `chat_id`, `user_id` without a
 * resolved name, r2 console fix m11): the tooltip and the chat view add this hint.
 */
export const UNRESOLVED_NAME_HINT = "(이름 미해석)";
const NAME_KEYS: ReadonlySet<string> = new Set([
  "sender",
  "recipient",
  "author",
  "conversation_title",
  "conversation_id",
  "chat_id",
  "chat_room",
  "author_id",
]);

/** True for a bare numeric id (5+ digits) where a name is expected. */
export function isUnresolvedNameId(value: unknown): boolean {
  return (typeof value === "string" || typeof value === "number") && /^-?\d{5,}$/.test(String(value).trim());
}

function nameColumn(def: CatalogColumn): boolean {
  return NAME_KEYS.has(def.key) || (def.semantic ?? "").startsWith("person");
}

/**
 * Korean reading of a raw catalogue value: `value_labels` (발신/수신/불명 for every app's raw
 * spelling, r2 console fix M7) or an artifact-type name (`format: artifact_type`); undefined = none.
 */
export function catalogValueReading(def: CatalogColumn, value: unknown): string | undefined {
  const mapped = columnValueLabel(def, value);
  if (mapped) return mapped;
  // The shared value-label table (R7 L3): `edge` → Edge, `fixed` → 고정 디스크 under any family.
  const shared = keyValueReading(def.key, value);
  if (shared) return shared;
  // A flag reads 예 / 아니오, never true / false (C9; the raw value stays in the tooltip).
  if (typeof value === "boolean") return value ? "예" : "아니오";
  if (def.format === "artifact_type" && typeof value === "string" && value) {
    return artifactTypeLabel(value) ?? undefined;
  }
  return undefined;
}

/** `0x1A2B` of a non-negative integer offset (`format: hex`); other values as written. */
function hexText(value: unknown): string | undefined {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return undefined;
  return `0x${Math.floor(value).toString(16).toUpperCase()}`;
}

/**
 * Prefetch volume table (`volumes` / `volume_candidates`): "장치 · 일련번호 · 생성 시각" per volume
 * (creation time in the display timezone), volumes separated by "; ".
 */
export function prefetchVolumesText(value: unknown): string {
  const list = Array.isArray(value) ? value : [value];
  return list
    .map((item) => {
      if (!isRecord(item)) return flatValue(item);
      const created = item.volume_created_at;
      return [
        flatValue(item.volume_device_path ?? item.device_path ?? ""),
        item.volume_serial_number ? `VSN ${flatValue(item.volume_serial_number)}` : "",
        typeof created === "string" && created ? `생성 ${formatGridTime(created, currentTimezone())}` : "",
      ]
        .filter(Boolean)
        .join(" · ");
    })
    .filter(Boolean)
    .join("; ");
}

function displayValue(def: CatalogColumn, value: unknown): string {
  const reading = catalogValueReading(def, value);
  if (reading) return reading;
  if (def.format === "time" && (typeof value === "string" || typeof value === "number")) {
    return formatGridTime(value, currentTimezone());
  }
  // A list of times (Prefetch's 8 run times): each in the display timezone, never raw UTC.
  if (def.format === "time" && Array.isArray(value)) {
    return clipValue(
      value
        .filter((item) => typeof item === "string" || typeof item === "number")
        .map((item) => formatGridTime(item as string | number, currentTimezone()))
        .join(", "),
      300,
    );
  }
  if (def.format === "prefetch_volumes") return clipValue(prefetchVolumesText(value), 300);
  if (def.format === "hex") {
    const hex = hexText(value);
    if (hex) return hex;
  }
  // Sizes: numbers, or digit strings (Amcache `size_bytes` is written as text, C9).
  if (
    def.format === "bytes" &&
    (typeof value === "number" || (typeof value === "string" && /^\d+$/.test(value)))
  )
    return formatBytes(Number(value));
  // Registry key path (registry family, P4): the last three parts; the full path is in the tooltip.
  if (def.format === "key_tail" && typeof value === "string") return keyTail(value);
  if (def.format === "logon_type" || def.format === "logonType")
    return logonTypeLabel(value) || flatValue(value);
  if (def.format === "eventLevel") return eventLevelLabel(value) || flatValue(value);
  if (def.format === "detectionSeverity") return severityLabel(value) || flatValue(value);
  // A list of attachment / item objects reads as their names, not JSON.
  if (Array.isArray(value) && value.some(isRecord)) {
    const names = value
      .map((item) =>
        isRecord(item)
          ? flatValue(item.name ?? item.filename ?? item.file_name ?? item.path ?? item.url ?? "")
          : flatValue(item),
      )
      .filter(Boolean);
    if (names.length) return clipValue(names.join(", "), 300);
  }
  // One object (synthetic-media `source_guess` {label, confidence, …}): its own label, never a
  // JSON preview (R7 L3, C-D9).
  if (isRecord(value)) {
    const label = value.label_ko ?? value.label ?? value.name ?? value.summary_ko ?? value.summary;
    if (typeof label === "string" && label) return clipValue(label, 300);
  }
  return clipValue(flatValue(value), 300);
}

/** Formats shown in the mono face (ids, hashes, SIDs, paths, URLs). */
const MONO_FORMATS: ReadonlySet<string> = new Set([
  "mono",
  "hex",
  "sid",
  "path",
  "url",
  "prefetch_volumes",
  "key_tail",
]);

/** "…\\Explorer\\RecentDocs\\.docx": the last three parts of a registry key path. */
export function keyTail(path: string, parts = 3): string {
  const segments = path.split("\\").filter(Boolean);
  return segments.length <= parts ? path : `…\\${segments.slice(-parts).join("\\")}`;
}

/** Default width of a catalogue column: a time cell holds its kind chip and the time (C7). */
export const TIME_COLUMN_WIDTH = 200;
/** Default width of a catalogue URL / path column: wide enough to read a host and a path (r7 S1). */
export const LINK_COLUMN_WIDTH = 240;
const LINK_FORMATS = new Set(["url", "path"]);

/**
 * A display-only catalogue column (`derive:`, axiom-adoption §3.2): computed from the row's own
 * fields, never sorted by the server; a value the parser cannot give reads "없음 — <사유>".
 */
function derivedCatalogColumn(def: CatalogColumn & { derive: string }, aux: boolean): ColumnSpec {
  const read = (row: GridRow) => deriveColumn(def.derive, detailsOf(row), row.artifactType ?? "");
  const text = (row: GridRow) => {
    const hit = read(row);
    if (!hit) return "";
    return "missing" in hit ? missingText(hit.missing) : hit.value;
  };
  return {
    id: familyColumnId(def.key),
    header: def.label,
    width: def.width ?? 150,
    minWidth: 60,
    presets: aux ? [] : ["analysis", "axiom"],
    fieldKeys: [],
    value: (row) => {
      const hit = read(row);
      return hit && !("missing" in hit) ? hit.value : null;
    },
    format: text,
    tooltip: (row) => {
      const hit = read(row);
      if (!hit) return "";
      if ("missing" in hit) return missingText(hit.missing);
      return hit.detail ? `${hit.value} (${hit.detail})` : hit.value;
    },
    render: (row) => {
      const hit = read(row);
      if (!hit) return createElement("span", { className: "grid-cell-empty", "aria-hidden": true }, "—");
      if ("missing" in hit)
        return createElement("span", { className: "grid-cell-missing" }, missingText(hit.missing));
      return createElement("span", { className: "grid-cell-text" }, hit.value);
    },
  };
}

/** Grid column of one catalogue column. `aux` columns start hidden (열 선택 › 카탈로그 보조 열). */
export function catalogColumn(def: CatalogColumn, aux = false): ColumnSpec {
  if (def.derive) return derivedCatalogColumn({ ...def, derive: def.derive }, aux);
  const numeric = def.format === "number" || def.format === "bytes";
  const sortable = !def.key.includes(".");
  const read = (row: { fields: Record<string, unknown> }) => readColumn(detailsOf(row), def);
  const tsKind = def.format === "time" ? def.ts_kind : undefined;
  return {
    id: familyColumnId(def.key),
    header: def.label,
    width:
      def.width ??
      (def.format === "time"
        ? TIME_COLUMN_WIDTH
        : LINK_FORMATS.has(def.format ?? "")
          ? LINK_COLUMN_WIDTH
          : 150),
    // A time never loses its seconds (C-D6, plan r7 §3.2 L2).
    minWidth: def.format === "time" ? TIME_COLUMN_MIN : 60,
    presets: aux ? [] : ["analysis", "axiom"],
    ...(MONO_FORMATS.has(def.format ?? "") ? { mono: true } : {}),
    ...(numeric ? { align: "right" as const, filterKind: "number" as const } : {}),
    ...(def.format === "time" ? { filterKind: "time" as const } : {}),
    ...(sortable ? { sortKey: `details.${def.key}` } : {}),
    ...(sortable && def.aliases?.length ? { sortHint: `${def.label} 정렬 (${def.key} 기준)` } : {}),
    fieldKeys: [def.key, ...(def.aliases ?? [])].filter((key) => !key.includes(".")),
    value: (row) => {
      const hit = read(row);
      if (!hit) return null;
      return typeof hit.value === "number" ? hit.value : flatValue(hit.value);
    },
    format: (row) => {
      const hit = read(row);
      return hit ? displayValue(def, hit.value) : "";
    },
    tooltip: (row) => {
      const hit = read(row);
      if (!hit) return "";
      // A shortened key path shows the whole path on hover.
      const text = def.format === "key_tail" ? flatValue(hit.value) : displayValue(def, hit.value);
      const rowKind = cellTsKind(def, detailsOf(row), hit.from) ?? tsKind;
      const kind = rowKind ? ` · ${tsKindLabel(rowKind)}(${rowKind})` : "";
      // The raw value stays readable behind a Korean reading ("발신 (원래 값: outgoing)").
      const raw = catalogValueReading(def, hit.value) ? ` (원래 값: ${flatValue(hit.value)})` : "";
      const hint = nameColumn(def) && isUnresolvedNameId(hit.value) ? ` ${UNRESOLVED_NAME_HINT}` : "";
      const shown = `${text}${raw}${hint}${kind}`;
      return hit.from === def.key ? shown : `${shown} — ${hit.from}`;
    },
    ...(tsKind
      ? {
          render: (row) => {
            const hit = read(row);
            if (!hit)
              return createElement("span", { className: "grid-cell-empty", "aria-hidden": true }, "—");
            const rowKind = cellTsKind(def, detailsOf(row), hit.from) ?? tsKind;
            // The column's own kind is its header ("마지막 방문", "수정"): a chip only when this
            // row's time is another kind ($FN vs $SI, key LastWrite vs value time …; C-D6).
            if (rowKind === tsKind) {
              return createElement("span", { className: "grid-cell-text" }, displayValue(def, hit.value));
            }
            return createElement(
              "span",
              { className: "ts-cell" },
              // Korean chip (기록 · 생성 · 마지막 …); the ts_kind id is in the tooltip.
              createElement(
                "span",
                { className: "ts-kind-chip", title: `${tsKindLabel(rowKind)} (${rowKind})` },
                tsKindLabel(rowKind),
              ),
              createElement("span", { className: "grid-cell-text" }, displayValue(def, hit.value)),
            );
          },
        }
      : {}),
  };
}

/** 특이사항 column (U-F4): grade chips; server sort `sort=flags` (grade first). */
export function flagsColumn(presets: ColumnSpec["presets"] = ["analysis", "compact", "axiom"]): ColumnSpec {
  return {
    id: "flags",
    header: "특이사항",
    width: 170,
    minWidth: 90,
    presets,
    filterKind: "none",
    sortKey: "flags",
    sortHint: "특이사항 정렬 (등급 우선)",
    value: (row) => {
      const flags = rowFlags(row);
      return flags.length ? flagSortValue(flags) : null;
    },
    format: (row) => {
      const flags = rowFlags(row);
      return flags.length ? flags.map((f) => `${f.grade} ${f.label}`).join(", ") : "";
    },
    tooltip: (row) => {
      const flags = rowFlags(row);
      return flags.length ? flagsAccessibleName(flags) : "";
    },
    render: (row) => createElement(FlagCell, { row }),
  };
}

export interface FamilyLayoutParts {
  title: ColumnSpec;
  review: ColumnSpec;
  type: ColumnSpec;
  /** Columns kept after the catalogue ones, off by default (generic time, summary, parser …). */
  rest: ColumnSpec[];
}

/**
 * A family's default layout: leading time column(s) · 항목 · 특이사항 · the other core columns in
 * catalogue order · 선별 · 유형 chip, then the auxiliary columns (hidden) and the rest.
 */
export function familyLayout(family: CatalogFamily, parts: FamilyLayoutParts): ColumnSpec[] {
  const core = family.core_columns.map((def) => catalogColumn(def));
  const lead: ColumnSpec[] = [];
  while (core.length && family.core_columns[lead.length]?.format === "time" && lead.length < 1) {
    lead.push(core.shift() as ColumnSpec);
  }
  const coreIds = new Set([...lead, ...core].map((c) => c.id));
  const aux = family.aux_columns.map((def) => catalogColumn(def, true)).filter((c) => !coreIds.has(c.id));
  const taken = new Set([...coreIds, ...aux.map((c) => c.id)]);
  return [
    ...lead,
    parts.title,
    flagsColumn(),
    ...core,
    parts.review,
    parts.type,
    ...aux,
    ...parts.rest.filter((c) => !taken.has(c.id) && c.id !== "flags"),
  ];
}

/** Priority of a family layout (responsive hiding, empty columns go first): 항목 > 특이사항 > core. */
export function familyWidthPriority(family: CatalogFamily): string[] {
  // R7 갈래 A: 중복 · 계열 last (hidden first; hidden while no loaded row has a value).
  return [
    "title",
    "flags",
    ...family.core_columns.map((def) => familyColumnId(def.key)),
    "review",
    "type",
    "dedup",
    "family",
  ];
}

/** Column ids of a family's auxiliary columns (열 선택 › 카탈로그 보조 열 모두 추가/제거). */
export function auxColumnIds(family: CatalogFamily): string[] {
  const core = new Set(family.core_columns.map((def) => familyColumnId(def.key)));
  return family.aux_columns.map((def) => familyColumnId(def.key)).filter((id) => !core.has(id));
}

// ---- mixed-family grids (U-F8): four summary columns with label-above-value cells ----------

export interface SummaryEntry {
  label: string;
  value: string;
}

/** Up to three non-time catalogue facts of the row's own family, in catalogue order. */
function rowFacts(row: Pick<GridRow, "artifactType" | "timestamp" | "fields">): {
  facts: SummaryEntry[];
  time: SummaryEntry | null;
} {
  const family = familyForType(row.artifactType);
  const details = detailsOf(row);
  const facts: SummaryEntry[] = [];
  let time: SummaryEntry | null = null;
  for (const def of family?.core_columns ?? []) {
    if (def.derive) {
      const derived = deriveColumn(def.derive, details, row.artifactType ?? "");
      if (derived && !("missing" in derived) && facts.length < 3)
        facts.push({ label: def.label, value: derived.value });
      continue;
    }
    const hit = readColumn(details, def);
    if (!hit) continue;
    const value = displayValue(def, hit.value).trim();
    if (!value) continue;
    if (def.format === "time") {
      if (!time) time = { label: def.ts_kind ? tsKindLabel(def.ts_kind) : def.label, value };
    } else if (facts.length < 3) facts.push({ label: def.label, value });
  }
  if (!time && row.timestamp) {
    time = { label: "시각", value: formatGridTime(row.timestamp, currentTimezone()) };
  }
  return { facts, time };
}

/**
 * Every core column of the family of `artifactType` that has a value in `details`, read like the
 * family grid reads it (viewer › 메타 of a timeline event, C10: the source row's core facts).
 */
export function familyCoreFacts(
  artifactType: string | null | undefined,
  details: Record<string, unknown>,
): { family: string; facts: SummaryEntry[] } | null {
  const family = familyForType(artifactType);
  if (!family) return null;
  const facts: SummaryEntry[] = [];
  for (const def of family.core_columns) {
    if (def.derive) {
      const derived = deriveColumn(def.derive, details, artifactType ?? "");
      if (derived && !("missing" in derived)) facts.push({ label: def.label, value: derived.value });
      continue;
    }
    const hit = readColumn(details, def);
    if (!hit) continue;
    const value = (def.format === "key_tail" ? flatValue(hit.value) : displayValue(def, hit.value)).trim();
    if (value) facts.push({ label: def.label, value });
  }
  return { family: family.label, facts };
}

/**
 * One line of an artifact row's own family facts ("실행 횟수: 5 · 볼륨: …"): the catalogue core
 * columns read from `details` (timeline 상세 column, timeline/grid readability C4). `skip` drops
 * facts that repeat another column's value (the 대상 column).
 */
export function familyFactsLine(
  artifactType: string | null | undefined,
  details: Record<string, unknown>,
  skip: readonly string[] = [],
): string {
  const { facts } = rowFacts({ artifactType: artifactType ?? null, timestamp: null, fields: { details } });
  const skipped = new Set(skip.map((value) => value.trim()).filter(Boolean));
  return facts
    .filter((fact) => !skipped.has(fact.value))
    .map((fact) => `${fact.label}: ${fact.value}`)
    .join(" · ");
}

/**
 * Memo shared by the four cells of one row, keyed by the display timezone and the catalogue in
 * effect too: rows keep their identity when either changes, the facts must not.
 */
const factsCache = new WeakMap<GridRow, { key: string; facts: ReturnType<typeof rowFacts> }>();
function factsOf(row: GridRow): ReturnType<typeof rowFacts> {
  const key = `${currentTimezone()}|${getCatalog().version}`;
  const hit = factsCache.get(row);
  if (hit && hit.key === key) return hit.facts;
  const facts = rowFacts(row);
  factsCache.set(row, { key, facts });
  return facts;
}

/**
 * The row's own family facts as the mixed grids read them (주요 · 지원 · 추가 · 날짜 및 시각): the
 * card view (C-V3) titles a row by its main fact when the row title is only the container file.
 */
export function rowSummaryFacts(row: GridRow): { facts: SummaryEntry[]; time: SummaryEntry | null } {
  return factsOf(row);
}

function twoLine(entry: SummaryEntry | null | undefined) {
  if (!entry) return createElement("span", { className: "grid-cell-empty", "aria-hidden": true }, "—");
  return createElement(
    "span",
    { className: "sum-cell" },
    createElement("span", { className: "sum-label" }, entry.label),
    createElement("span", { className: "sum-value" }, entry.value),
  );
}

function summaryColumn(
  id: string,
  header: string,
  pick: (row: GridRow) => SummaryEntry | null | undefined,
  width: number,
): ColumnSpec {
  return {
    id,
    header,
    width,
    minWidth: 120,
    presets: ["analysis", "compact", "axiom"],
    filterKind: "text",
    value: (row) => pick(row)?.value ?? null,
    format: (row) => {
      const entry = pick(row);
      return entry ? `${entry.label}: ${entry.value}` : "";
    },
    tooltip: (row) => {
      const entry = pick(row);
      return entry ? `${entry.label}: ${entry.value}` : "";
    },
    render: (row) => twoLine(pick(row)),
  };
}

/** 주요 · 지원 · 추가 세부 정보 · 날짜 및 시각 (rows of several families in one grid). */
export function mixedSummaryColumns(): ColumnSpec[] {
  return [
    summaryColumn("sum:main", "주요 세부 정보", (row) => factsOf(row).facts[0], 220),
    summaryColumn("sum:support", "지원 세부 정보", (row) => factsOf(row).facts[1], 180),
    summaryColumn("sum:extra", "추가 세부 정보", (row) => factsOf(row).facts[2], 180),
    summaryColumn("sum:time", "날짜 및 시각", (row) => factsOf(row).time, TIME_COLUMN_WIDTH),
  ];
}

/**
 * Category labels that never collide (R7 L3, C-V1 "레지스트리 하이브"×3): a label shared by several
 * entries is qualified by the entry's `context` (its tree group: "실행 흔적 · 운영체제·계정"), and
 * entries still sharing a label after that are numbered. Never a raw id. Order is kept.
 */
export function uniqueLabels<T extends { label: string; context?: string }>(entries: readonly T[]): T[] {
  const count = (list: readonly { label: string }[]) => {
    const uses = new Map<string, number>();
    for (const entry of list) uses.set(entry.label, (uses.get(entry.label) ?? 0) + 1);
    return uses;
  };
  const first = count(entries);
  const qualified = entries.map((entry) =>
    (first.get(entry.label) ?? 0) > 1 && entry.context && entry.context !== entry.label
      ? { ...entry, label: `${entry.label} · ${entry.context}` }
      : entry,
  );
  const second = count(qualified);
  const seen = new Map<string, number>();
  return qualified.map((entry) => {
    if ((second.get(entry.label) ?? 0) < 2) return entry;
    const nth = (seen.get(entry.label) ?? 0) + 1;
    seen.set(entry.label, nth);
    return nth > 1 ? { ...entry, label: `${entry.label} (${nth})` } : entry;
  });
}
