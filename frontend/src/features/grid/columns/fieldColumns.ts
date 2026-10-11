/**
 * Promoted record-field columns (plan artifact-columns U-C1).
 *
 * Any scalar (or scalar-array) `details` key of an artifact kind can become a
 * grid column: id `f:<key>`, server sort key `details.<key>`. The promoted set
 * lives in the URL (`cols=details.a,details.b`) and per kind in localStorage
 * (`rapidtriage.grid.fieldColumns.artifacts.<kind>`); the URL wins when present.
 */

import type { GridRow } from "../../../contracts/collection";
import { isServerSortKey } from "../../../router";
import { clipValue, flatValue, isScalarish } from "../../../utils/flatValue";
import type { ColumnSpec } from "../types";
import { isRecord } from "./common";

export const FIELD_COLUMN_PREFIX = "f:";
const DETAILS_PREFIX = "details.";

export const fieldColumnId = (key: string): string => `${FIELD_COLUMN_PREFIX}${key}`;
export const fieldSortKey = (key: string): string => `${DETAILS_PREFIX}${key}`;

/** URL `cols` entries (`details.<key>`) -> details keys. */
export function colsToKeys(cols: readonly string[] | undefined): string[] {
  return (cols ?? []).filter((c) => c.startsWith(DETAILS_PREFIX)).map((c) => c.slice(DETAILS_PREFIX.length));
}

export function keysToCols(keys: readonly string[]): string[] {
  return keys.map(fieldSortKey);
}

export function fieldColumnsStorageKey(kind: string): string {
  return `rapidtriage.grid.fieldColumns.artifacts.${kind}`;
}

/** Stored promoted columns of a kind (URL form); null when nothing (or nothing readable) is stored. */
export function readStoredFieldColumns(kind: string): string[] | null {
  try {
    const raw = window.localStorage.getItem(fieldColumnsStorageKey(kind));
    if (raw === null) return null;
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return null;
    return parsed.filter((c): c is string => typeof c === "string" && c.startsWith(DETAILS_PREFIX));
  } catch {
    return null;
  }
}

export function writeStoredFieldColumns(kind: string, cols: readonly string[]): void {
  try {
    window.localStorage.setItem(fieldColumnsStorageKey(kind), JSON.stringify(cols));
  } catch {
    // Storage unavailable: the promoted columns still ride in the URL.
  }
}

/** The promoted columns in effect: the URL's when it has any, else the kind's stored set. */
export function effectiveFieldCols(
  routeCols: readonly string[] | undefined,
  kind: string | undefined,
): string[] {
  if (!kind) return [];
  if (routeCols?.length) return [...routeCols];
  return readStoredFieldColumns(kind) ?? [];
}

/** Add or remove one details key (URL form list). */
export function toggleFieldCol(cols: readonly string[], key: string, on?: boolean): string[] {
  const col = fieldSortKey(key);
  const has = cols.includes(col);
  const want = on ?? !has;
  if (want === has) return [...cols];
  return want ? [...cols, col] : cols.filter((c) => c !== col);
}

/** Korean headers for well-known details keys (plan §4.3); other keys show the key itself. */
export const FIELD_LABELS: Record<string, string> = {
  level: "레벨",
  computer: "컴퓨터",
  user_name: "사용자",
  executable_hint: "실행 파일",
  header_executable_name: "실행 파일",
  run_count: "실행 횟수",
  last_run_at: "최근 실행",
  referenced_path: "참조 경로",
  prefetch_parse_status: "파싱 상태",
  hive_name: "하이브",
  cell_kind: "셀 종류",
  name: "이름",
  value_type: "값 유형",
  last_written_at: "마지막 기록",
  cell_offset: "셀 오프셋",
  source_key_path: "키 경로",
  key_last_written_at: "마지막 기록",
  parser_confidence: "신뢰도",
  target_path: "대상 경로",
  target_modified_at: "대상 수정",
  target_file_size: "대상 크기",
  command_line_arguments: "인수",
  working_dir: "작업 폴더",
  executable_path: "실행 경로",
  program_name: "프로그램",
  publisher: "게시자",
  version: "버전",
  sha1: "SHA-1",
  application_name: "앱",
  application_path: "앱 경로",
  fault_module_name: "오류 모듈",
  event_time: "이벤트 시각",
  report_id: "보고서 ID",
  user_name_candidate: "계정",
  rid_decimal: "RID",
  account_type_hint: "역할",
  profile_path: "프로필 경로",
  detected_signature_kind: "감지 서명",
  expected_extensions: "기대 확장자",
  source_size: "크기",
  modified_at: "수정",
  risk_flags: "위험",
  entry_name: "이름",
  source_format: "형식",
  visual_classification: "분류",
  conversation_id: "대화",
  chat_id: "대화",
  message_text_preview: "메시지",
  attachment_name: "첨부",
  source_app_identifier: "앱",
  participants: "참여자",
  document_family: "문서 군",
  author_candidates: "작성자 후보",
};

const HASHY_KEY = /(^|_)(sha1|sha256|sha512|md5|hash|hex)($|_)/i;

/** Raw details value of a row (artifact rows keep `details` under fields). */
export function detailOf(row: GridRow, key: string): unknown {
  const details = row.fields.details;
  return isRecord(details) ? details[key] : undefined;
}

/** Same predicate as the URL (`router.isServerSortKey`): no whitespace, comma or colon. */
export function isShareableFieldKey(key: string): boolean {
  return isServerSortKey(fieldSortKey(key));
}

export const UNSHAREABLE_FIELD_REASON = "열 이름에 공백/쉼표/콜론이 있어 공유 링크에 담을 수 없습니다";
export const LIST_FIELD_SORT_REASON = "목록 값은 전체 정렬을 지원하지 않습니다";

export interface PromotedColumnOptions {
  /** The key holds lists in the loaded rows: shown as a comma list, never server-sorted. */
  list?: boolean;
  /** Headers already used by the default columns: a colliding label becomes "라벨 (key)". */
  takenHeaders?: ReadonlySet<string>;
}

/** Column for one promoted details key. Visible in every preset (survives preset changes). */
export function promotedColumn(key: string, options: PromotedColumnOptions = {}): ColumnSpec {
  const label = FIELD_LABELS[key];
  const header = label ? (options.takenHeaders?.has(label) ? `${label} (${key})` : label) : key;
  return {
    id: fieldColumnId(key),
    header,
    width: 160,
    minWidth: 60,
    mono: HASHY_KEY.test(key),
    presets: ["analysis", "compact", "source", "axiom"],
    ...(options.list ? { unsortableReason: LIST_FIELD_SORT_REASON } : { sortKey: fieldSortKey(key) }),
    fieldKeys: [key],
    value: (row) => {
      const v = detailOf(row, key);
      return typeof v === "number" ? v : flatValue(v);
    },
    format: (row) => clipValue(flatValue(detailOf(row, key))),
  };
}

export interface DiscoveredField {
  key: string;
  /** Loaded rows that carry a non-empty scalar value for the key. */
  count: number;
  /** Loaded rows that carry the key at all (scalar, scalar list, empty string or null). */
  present?: number;
  /** Some loaded row holds a list for the key (not server sortable). */
  list?: true;
  /** The key cannot ride in a URL (whitespace / comma / colon): offered greyed with a reason. */
  unshareable?: true;
}

/** Keys of `keys` that hold a list in any of the rows (promoted columns of list keys are unsortable). */
export function listKeysIn(rows: readonly GridRow[], keys: readonly string[]): Set<string> {
  const out = new Set<string>();
  if (keys.length === 0) return out;
  for (const row of rows) {
    const details = row.fields.details;
    if (!isRecord(details)) continue;
    for (const key of keys) if (Array.isArray(details[key])) out.add(key);
    if (out.size === keys.length) break;
  }
  return out;
}

/**
 * The union of scalar / scalar-array `details` keys over EVERY loaded row (all fetched
 * pages, any artifact type), most filled first; keys present only with empty values are
 * still listed (count 0). Keys the given columns already show (`fieldKeys`) are left out.
 */
export function discoverFields(rows: readonly GridRow[], columns: readonly ColumnSpec[]): DiscoveredField[] {
  const covered = new Set<string>();
  for (const column of columns) {
    if (column.id.startsWith(FIELD_COLUMN_PREFIX)) continue;
    for (const key of column.fieldKeys ?? []) covered.add(key);
  }
  const counts = new Map<string, { count: number; present: number; list: boolean }>();
  for (const row of rows) {
    const details = row.fields.details;
    if (!isRecord(details)) continue;
    for (const [key, value] of Object.entries(details)) {
      if (covered.has(key) || !(value === null || isScalarish(value))) continue;
      const entry = counts.get(key) ?? { count: 0, present: 0, list: false };
      entry.present += 1;
      if (Array.isArray(value)) entry.list = true;
      if (flatValue(value) !== "") entry.count += 1;
      counts.set(key, entry);
    }
  }
  return [...counts.entries()]
    .map(
      ([key, { count, present, list }]): DiscoveredField => ({
        key,
        count,
        present,
        ...(list ? { list: true as const } : {}),
        ...(isShareableFieldKey(key) ? {} : { unshareable: true as const }),
      }),
    )
    .sort((a, b) => b.count - a.count || (b.present ?? 0) - (a.present ?? 0) || a.key.localeCompare(b.key));
}

/** Field list for the column menu: discovered keys plus promoted keys absent from the loaded rows, filtered by search. */
export function fieldMenuEntries(
  discovered: readonly DiscoveredField[],
  promotedKeys: readonly string[],
  search: string,
): DiscoveredField[] {
  const seen = new Set(discovered.map((f) => f.key));
  const all = [...discovered, ...promotedKeys.filter((k) => !seen.has(k)).map((key) => ({ key, count: 0 }))];
  const needle = search.trim().toLowerCase();
  if (!needle) return all;
  return all.filter(
    (f) => f.key.toLowerCase().includes(needle) || (FIELD_LABELS[f.key] ?? "").toLowerCase().includes(needle),
  );
}
