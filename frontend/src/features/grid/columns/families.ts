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
import { deriveColumn, missingText } from "../../derived/derivedFields";
import { type CatalogColumn, type CatalogFamily, familyForType, getCatalog } from "../../flags/catalog";
import { FlagCell } from "../../flags/FlagCell";
import { flagSortValue, flagsAccessibleName, rowFlags } from "../../flags/flags";
import { eventLevelLabel, logonTypeLabel, severityLabel } from "../../viewer/fieldFormat";
import { EVENT_DATA_KEYS } from "../../viewer/fieldSheets";
import type { ColumnSpec } from "../types";
import { currentTimezone, formatBytes, isRecord } from "./common";

/** Korean reading of a timestamp kind (chip tooltip / accessible text). */
export const TS_KIND_LABELS: Record<string, string> = {
  // backend catalogue (rapidtriage/core/triage_rules/catalog/*.yaml)
  logged: "기록 시각",
  "account-expires": "계정 만료",
  "download-start": "다운로드 시작",
  "download-end": "다운로드 완료",
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
  return TS_KIND_LABELS[kind] ?? TS_KIND_LABELS[kind.replace(/-/g, "_")] ?? `시각 종류: ${kind}`;
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

/** One candidate key: a top-level key, `event_data.X` (any EVTX EventData container) or a dotted path. */
export function readKey(details: Record<string, unknown>, key: string): unknown {
  if (!key.includes(".")) return details[key];
  const [head, ...rest] = key.split(".");
  const containers = head === "event_data" ? EVENT_DATA_KEYS : [head as string];
  for (const name of containers) {
    let value: unknown = details[name];
    for (const part of rest) value = isRecord(value) ? value[part] : undefined;
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

function displayValue(def: CatalogColumn, value: unknown): string {
  if (def.format === "time" && (typeof value === "string" || typeof value === "number")) {
    return formatGridTime(value, currentTimezone());
  }
  if (def.format === "bytes" && typeof value === "number") return formatBytes(value);
  if (def.format === "logon_type" || def.format === "logonType")
    return logonTypeLabel(value) || flatValue(value);
  if (def.format === "eventLevel") return eventLevelLabel(value) || flatValue(value);
  if (def.format === "detectionSeverity") return severityLabel(value) || flatValue(value);
  return clipValue(flatValue(value), 300);
}

/** Formats shown in the mono face (ids, hashes, SIDs, paths, URLs). */
const MONO_FORMATS: ReadonlySet<string> = new Set(["mono", "hex", "sid", "path", "url"]);

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
    width: def.width ?? (def.format === "time" ? 170 : 150),
    minWidth: 60,
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
      const text = displayValue(def, hit.value);
      const kind = tsKind ? ` · ${tsKindLabel(tsKind)}(${tsKind})` : "";
      return hit.from === def.key ? `${text}${kind}` : `${text}${kind} — ${hit.from}`;
    },
    ...(tsKind
      ? {
          render: (row) => {
            const hit = read(row);
            if (!hit)
              return createElement("span", { className: "grid-cell-empty", "aria-hidden": true }, "—");
            return createElement(
              "span",
              { className: "ts-cell" },
              // Korean chip (기록 · 생성 · 마지막 …); the catalogue's ts_kind id is in the tooltip.
              createElement(
                "span",
                { className: "ts-kind-chip", title: `${tsKindLabel(tsKind)} (${tsKind})` },
                tsKindLabel(tsKind),
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
  return ["title", "flags", ...family.core_columns.map((def) => familyColumnId(def.key)), "review", "type"];
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
function rowFacts(row: GridRow): { facts: SummaryEntry[]; time: SummaryEntry | null } {
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
    summaryColumn("sum:time", "날짜 및 시각", (row) => factsOf(row).time, 170),
  ];
}
