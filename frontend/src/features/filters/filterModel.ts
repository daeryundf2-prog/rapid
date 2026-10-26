/**
 * Filter model (X19): pure state, URL mapping, server/client partitioning and
 * the client-side row predicate. No React, no stores.
 *
 * Server-capable filters (checked against the API, console-redesign S8 and
 * analysis-workbench-p1 §4):
 *  - artifacts: `path_contains` (path text / 경로 column filter), `artifact_type=`
 *               (types / 유형 column filter, repeated), `browser=` / `service=`
 *               (exact record fields of a tree node, repeated), `channel=` / `channel_group=`
 *               (`evt_channel` / `evt_channel_group` column filters: exact names or group ids
 *               joined by "|"; the 이벤트 로그 channel nodes use the group filter)
 *  - analysis:  `path_contains` (path text / 경로 column filter)
 *  - search:    `extension` (repeated param; 확장자 column filter too)
 *  - artifacts/files/timeline (r4 §2.3 row conditions): time range (`from`/`to`), 요일·시간대·업무
 *               외 시간 (`weekday`/`hours`/`offhours` + `tz`), 부분 결과 (`partial`), 콘텐츠 유형
 *               (`content`); artifacts also the map cluster box (`geo`)
 *  - docs/indicators/search/analysis: those row conditions run on the loaded rows
 * Everything else (review status, tags, other column filters) runs on the rows already
 * loaded; the filter status line says so.
 */

import { ANALYSIS_DETAIL_FILTER_KEYS } from "../../api/analyses";
import {
  type CollectionQuery,
  type CollectionRef,
  type ColumnFilter,
  type GridRow,
  hasRecordFields,
  RECORD_FIELD_KEYS,
  RECORD_FIELD_LABELS,
  type RecordFieldFilters,
  type RecordFieldKey,
  type ReviewStatus,
  recordFieldsKey,
} from "../../contracts/collection";
import type { Route } from "../../router";
import { parseInstant } from "../../utils/time";
import { CARVE_KINDS } from "../analysis/analysisForm";
import { type Grade, isGrade } from "../flags/catalog";
import { rowMatchesFlagFilter, ruleLabel } from "../flags/flags";
import { contentTypeLabel } from "./contentTypes";
import {
  clockLabel,
  hasClock,
  orderedRange,
  parseGeo,
  rowMatchesConditions,
  type ServerConditionParams,
  serverConditionParams,
  timeWindow,
} from "./rowConditions";

export interface FilterState {
  /** Inclusive lower bound (ISO or `YYYY-MM-DDTHH:mm`). */
  from?: string;
  to?: string;
  statuses: ReviewStatus[];
  types: string[];
  tags: string[];
  /** Extensions, lower-case, no leading dot. */
  ext: string[];
  path: string;
  /** Only rows with a review note (URL `note=1`). */
  notes?: boolean;
  /** Column header filters (URL `cf=`). */
  columns: ColumnFilter[];
  /** 특이사항 rules (URL `flag=`, repeated; any of them). */
  flags?: string[];
  /** 특이사항 grade at least (URL `flag_grade=A|B|C`). */
  flagGrade?: Grade;
  /** Exact record fields (URL `browser=` / `service=`; artifacts server-side). */
  fields?: RecordFieldFilters;
  /** Weekdays of the row time, `mon`..`sun` (URL `wd=`). */
  weekdays?: string[];
  /** Hour-of-day window `HH-HH` (URL `hours=`). */
  hours?: string;
  /** 업무 외 시간: hours OR weekdays, defaults 18-09 · sat,sun (URL `offhours=1`). */
  offhours?: boolean;
  /** 부분 결과 rows only (URL `partial=1`). */
  partial?: boolean;
  /** 콘텐츠 유형 ids (URL `content=`). */
  content?: string[];
  /** Map cluster box `lat0,lon0,lat1,lon1` (URL `geo=`). */
  geo?: string;
}

export const EMPTY_FILTERS: FilterState = Object.freeze({
  statuses: [],
  types: [],
  tags: [],
  ext: [],
  path: "",
  columns: [],
}) as FilterState;

/**
 * Korean artifact-type names for the 유형 chips (R7 L3). Registered by grid/valueLabels: the type
 * table lives with the tree (tree/domains imports this module), so a direct import would cycle.
 */
let chipTypeLabel: (type: string) => string | null = () => null;

export function setChipTypeLabel(resolve: (type: string) => string | null): void {
  chipTypeLabel = resolve;
}

export function normalizeExt(value: string): string {
  return value.trim().replace(/^\.+/, "").toLowerCase();
}

export function filtersFromRoute(route: Route): FilterState {
  return {
    ...(route.from ? { from: route.from } : {}),
    ...(route.to ? { to: route.to } : {}),
    statuses: route.statuses ?? [],
    types: route.types ?? [],
    tags: route.tags ?? [],
    ext: (route.ext ?? []).map(normalizeExt).filter(Boolean),
    path: route.path ?? "",
    ...(route.notes ? { notes: true } : {}),
    columns: route.cf ?? [],
    ...(route.flags?.length ? { flags: route.flags } : {}),
    ...(route.flagGrade ? { flagGrade: route.flagGrade } : {}),
    ...(hasRecordFields(route.fields) ? { fields: route.fields } : {}),
    ...(route.weekdays?.length ? { weekdays: route.weekdays } : {}),
    ...(route.hours ? { hours: route.hours } : {}),
    ...(route.offhours ? { offhours: true } : {}),
    ...(route.partial ? { partial: true } : {}),
    ...(route.content?.length ? { content: route.content } : {}),
    ...(route.geo ? { geo: route.geo } : {}),
  };
}

/** Route patch for a filter state; empty parts are `undefined` so `patchRoute` clears them. */
export function filtersToRoutePatch(filters: FilterState): Partial<Route> {
  return {
    from: filters.from || undefined,
    to: filters.to || undefined,
    statuses: filters.statuses.length ? filters.statuses : undefined,
    types: filters.types.length ? filters.types : undefined,
    tags: filters.tags.length ? filters.tags : undefined,
    ext: filters.ext.length ? filters.ext : undefined,
    path: filters.path || undefined,
    notes: filters.notes ? true : undefined,
    cf: filters.columns?.length ? filters.columns : undefined,
    flags: filters.flags?.length ? filters.flags : undefined,
    flagGrade: filters.flagGrade && isGrade(filters.flagGrade) ? filters.flagGrade : undefined,
    fields: hasRecordFields(filters.fields) ? filters.fields : undefined,
    weekdays: filters.weekdays?.length ? filters.weekdays : undefined,
    hours: filters.hours || undefined,
    offhours: filters.offhours ? true : undefined,
    partial: filters.partial ? true : undefined,
    content: filters.content?.length ? filters.content : undefined,
    geo: filters.geo && parseGeo(filters.geo) ? filters.geo : undefined,
  };
}

function columnsKey(columns: readonly ColumnFilter[] | undefined): string {
  return JSON.stringify((columns ?? []).map((f) => [f.col, f.op, f.value]));
}

export function filtersEqual(a: FilterState, b: FilterState): boolean {
  return (
    (a.from ?? "") === (b.from ?? "") &&
    (a.to ?? "") === (b.to ?? "") &&
    a.path === b.path &&
    Boolean(a.notes) === Boolean(b.notes) &&
    a.statuses.join() === b.statuses.join() &&
    a.types.join() === b.types.join() &&
    a.tags.join() === b.tags.join() &&
    a.ext.join() === b.ext.join() &&
    (a.flags ?? []).join() === (b.flags ?? []).join() &&
    (a.flagGrade ?? "") === (b.flagGrade ?? "") &&
    recordFieldsKey(a.fields) === recordFieldsKey(b.fields) &&
    columnsKey(a.columns) === columnsKey(b.columns) &&
    (a.weekdays ?? []).join() === (b.weekdays ?? []).join() &&
    (a.hours ?? "") === (b.hours ?? "") &&
    Boolean(a.offhours) === Boolean(b.offhours) &&
    Boolean(a.partial) === Boolean(b.partial) &&
    (a.content ?? []).join() === (b.content ?? []).join() &&
    (a.geo ?? "") === (b.geo ?? "")
  );
}

export function hasActiveFilters(filters: FilterState): boolean {
  return !filtersEqual(filters, EMPTY_FILTERS);
}

// --- time presets -----------------------------------------------------------

/** Relative ranges (r4 §2.3): 오늘 and 최근 1 / 7 / 30일, ending now. */
export type TimePreset = "today" | "1d" | "7d" | "30d";

export const TIME_PRESET_LABELS: Record<TimePreset, string> = {
  today: "오늘",
  "1d": "최근 1일",
  "7d": "최근 7일",
  "30d": "최근 30일",
};

const PRESET_DAYS: Record<Exclude<TimePreset, "today">, number> = { "1d": 1, "7d": 7, "30d": 30 };

/** Local `YYYY-MM-DDTHH:mm` (the value format of `<input type="datetime-local">`). */
export function toLocalInput(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** Value for `<input type="datetime-local">` from any ISO bound (S10 clock buttons pass ISO with Z). */
export function toInputValue(value: string | undefined): string {
  if (!value) return "";
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) return value;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? "" : toLocalInput(new Date(ms));
}

export function presetRange(preset: TimePreset, now: Date = new Date()): { from: string; to: string } {
  const start = new Date(now);
  if (preset === "today") start.setHours(0, 0, 0, 0);
  else start.setTime(now.getTime() - PRESET_DAYS[preset] * 86_400_000);
  return { from: toLocalInput(start), to: toLocalInput(now) };
}

/** Which preset (if any) the current range equals, with a minute of slack. */
export function activePreset(filters: FilterState, now: Date = new Date()): TimePreset | null {
  if (!filters.from || !filters.to) return null;
  for (const preset of ["today", "1d", "7d", "30d"] as const) {
    const range = presetRange(preset, now);
    if (
      Math.abs(Date.parse(range.from) - Date.parse(filters.from)) <= 60_000 &&
      Math.abs(Date.parse(range.to) - Date.parse(filters.to)) <= 60_000
    )
      return preset;
  }
  return null;
}

// --- partitioning -----------------------------------------------------------

/** Collections whose API applies the row conditions (r4 §2.3: time, clock, 부분 결과, 콘텐츠 유형). */
export const CONDITION_SERVER_COLLECTIONS: ReadonlySet<string> = new Set(["artifacts", "files", "timeline"]);

/** Collections whose API filters 특이사항 (`flag=` / `flag_grade=`, plan §3.1 조인). */
export const FLAG_SERVER_COLLECTIONS: ReadonlySet<string> = new Set(["artifacts", "files", "analysis"]);

export interface FilterPlan {
  server: {
    path?: string;
    extension?: string[];
    artifactTypes?: string[];
    channels?: string[];
    channelGroups?: string[];
    flags?: string[];
    flagGrade?: Grade;
    fields?: RecordFieldFilters;
    /** Analysis rows: exact `details` filters (`f:source` / `f:signature_kind` / `f:recovery_method` / `f:in_use`). */
    details?: Record<string, string[]>;
    /** Row-condition query params (`from`, `to`, `weekday`, `hours`, `offhours`, `tz`, `partial`, `content`, `geo`). */
    conditions?: ServerConditionParams;
  };
  /** Column filters the client applies to loaded rows (the rest went to the API). */
  clientColumns: ColumnFilter[];
  /** Column filters the API applies (경로 → path_contains, 유형 → artifact_type, 확장자 → extension). */
  serverColumns: ColumnFilter[];
  /** Korean names of filters the API applies. */
  serverLabels: string[];
  /** Korean names of filters applied only to loaded rows. */
  clientLabels: string[];
}

/**
 * Column id of the event-log channel filter (`cf=evt_channel:<names>`, not the 채널 grid column whose
 * header filter stays a substring match on loaded rows): exact channel names joined by
 * "|", applied server-side only (`channel=`, repeated) — never a substring match on loaded rows.
 */
export const CHANNEL_FILTER_COLUMN = "evt_channel";
/** Column id of the event-log channel *group* filter (`cf=evt_channel_group:security`): server `channel_group=`. */
export const CHANNEL_GROUP_FILTER_COLUMN = "evt_channel_group";

/** `Security|System` → ["Security", "System"] (trimmed, empty parts dropped). */
export function parseChannelFilterValue(value: string): string[] {
  return value
    .split("|")
    .map((part) => part.trim())
    .filter(Boolean);
}

/** `f:<key>` column of an analysis `details` key the rows API filters exactly, else null. */
export function analysisDetailKey(col: string): string | null {
  const key = col.startsWith("f:") ? col.slice(2) : "";
  return ANALYSIS_DETAIL_FILTER_KEYS.includes(key) ? key : null;
}

/** Decide which active filters go to the API for this collection and which stay on the client. */
/**
 * Server artifact types a 유형 column text selects: an exact known type as-is, else every
 * known type containing the text (case-insensitive) — the server filter is exact
 * (`artifact_type=`), so "wer" is sent as the run's matching types, never as "wer". Without
 * known types (no `/tree` counts) the text is sent as typed.
 */
export function typeMatches(text: string, knownTypes: readonly string[]): string[] {
  const value = text.trim();
  if (!value || knownTypes.length === 0 || knownTypes.includes(value)) return [value];
  const needle = value.toLowerCase();
  const hits = knownTypes.filter((type) => type.toLowerCase().includes(needle));
  return hits.length ? [...hits].sort() : [value];
}

export function partitionFilters(
  ref: CollectionRef,
  filters: FilterState,
  knownTypes: readonly string[] = [],
  tz = "utc",
): FilterPlan {
  const server: FilterPlan["server"] = {};
  const serverLabels: string[] = [];
  const clientLabels: string[] = [];
  const clientColumns: ColumnFilter[] = [];
  const serverColumns: ColumnFilter[] = [];
  const pathOnServer = ref.id === "artifacts" || ref.id === "analysis";
  let typeColumn: "exact" | "contains" | null = null;

  const conditionLabels: string[] = [];
  if (filters.from || filters.to) conditionLabels.push("시간 범위");
  if (hasClock(filters)) conditionLabels.push(filters.offhours ? "업무 외 시간" : "요일·시간대");
  if (filters.partial) conditionLabels.push("부분 결과");
  if (filters.content?.length) conditionLabels.push("콘텐츠 유형");
  const geoOnServer = ref.id === "artifacts";
  if (CONDITION_SERVER_COLLECTIONS.has(ref.id)) {
    const params = serverConditionParams(filters, tz, { time: true, geo: geoOnServer });
    if (Object.keys(params).length) server.conditions = params;
    serverLabels.push(...conditionLabels);
    if (parseGeo(filters.geo)) (geoOnServer ? serverLabels : clientLabels).push("위치");
  } else {
    clientLabels.push(...conditionLabels);
    if (parseGeo(filters.geo)) clientLabels.push("위치");
  }
  if (filters.statuses.length) clientLabels.push("상태");
  if (filters.tags.length) clientLabels.push("태그");
  if (filters.notes) clientLabels.push("메모 있음");
  if (filters.flags?.length || filters.flagGrade) {
    if (FLAG_SERVER_COLLECTIONS.has(ref.id)) {
      if (filters.flags?.length) server.flags = [...filters.flags];
      if (filters.flagGrade) server.flagGrade = filters.flagGrade;
      serverLabels.push("특이사항");
    } else clientLabels.push("특이사항");
  }

  if (hasRecordFields(filters.fields)) {
    const names = RECORD_FIELD_KEYS.filter((key) => filters.fields?.[key]?.length).map(
      (key) => RECORD_FIELD_LABELS[key],
    );
    if (ref.id === "artifacts") {
      server.fields = filters.fields;
      serverLabels.push(...names);
    } else clientLabels.push(...names);
  }
  if (filters.types.length) {
    if (ref.id === "artifacts") {
      server.artifactTypes = [...filters.types];
      serverLabels.push("유형");
    } else clientLabels.push("유형");
  }
  if (filters.ext.length) {
    if (ref.id === "search") {
      server.extension = [...filters.ext];
      serverLabels.push("확장자");
    } else clientLabels.push("확장자");
  }
  if (filters.path) {
    if (pathOnServer) {
      server.path = filters.path;
      serverLabels.push("경로");
    } else clientLabels.push("경로");
  }

  for (const filter of filters.columns ?? []) {
    const contains = filter.op === ":";
    if (contains && filter.col === "path" && pathOnServer && !server.path) {
      server.path = filter.value;
      serverColumns.push(filter);
    } else if (contains && filter.col === "type" && ref.id === "artifacts") {
      // 유형: the known types containing the text (or the exact type), AND-ed with the
      // filter-bar types (intersection).
      const bar = filters.types;
      const matched = typeMatches(filter.value, knownTypes);
      const kept = bar.length ? matched.filter((type) => bar.includes(type)) : matched;
      if (kept.length === 0) {
        // Empty intersection: the bar types stay on the server, the column match empties the rows.
        clientColumns.push(filter);
      } else {
        server.artifactTypes = kept;
        serverColumns.push(filter);
        typeColumn = kept.length === 1 && kept[0] === filter.value.trim() ? "exact" : "contains";
      }
    } else if (contains && filter.col === CHANNEL_FILTER_COLUMN && ref.id === "artifacts") {
      // 이벤트 로그 채널 노드: exact channel names, sent as repeated `channel=`.
      const channels = parseChannelFilterValue(filter.value);
      if (channels.length) {
        server.channels = [...new Set([...(server.channels ?? []), ...channels])];
        serverColumns.push(filter);
      } else clientColumns.push(filter);
    } else if (contains && filter.col === CHANNEL_GROUP_FILTER_COLUMN && ref.id === "artifacts") {
      const groups = parseChannelFilterValue(filter.value);
      if (groups.length) {
        server.channelGroups = [...new Set([...(server.channelGroups ?? []), ...groups])];
        serverColumns.push(filter);
      } else clientColumns.push(filter);
    } else if (contains && ref.id === "analysis" && analysisDetailKey(filter.col)) {
      // R3 §3.3: exact server filter on the rows' `details` (comma = any of).
      const key = analysisDetailKey(filter.col) as string;
      const values = filter.value
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
      if (values.length) {
        server.details = { ...(server.details ?? {}), [key]: values };
        serverColumns.push(filter);
      } else clientColumns.push(filter);
    } else if (contains && filter.col === "extension" && ref.id === "search") {
      const ext = normalizeExt(filter.value);
      server.extension = [...new Set([...(server.extension ?? []), ext])];
      serverColumns.push(filter);
    } else clientColumns.push(filter);
  }
  if (typeColumn === "exact") serverLabels.push("유형(정확히)");
  else if (typeColumn === "contains")
    serverLabels.push(`유형(포함: ${(server.artifactTypes ?? []).length}개 유형)`);
  if (server.channels?.length || server.channelGroups?.length) serverLabels.push("채널");
  if (
    serverColumns.some((f) => !["type", CHANNEL_FILTER_COLUMN, CHANNEL_GROUP_FILTER_COLUMN].includes(f.col))
  )
    serverLabels.push("열 필터");
  if (clientColumns.length) clientLabels.push("열 필터");
  return { server, serverLabels, clientLabels, clientColumns, serverColumns };
}

/** The filters the client must still apply: those the API already handled are blanked out. */
export function clientOnlyFilters(filters: FilterState, plan: FilterPlan): FilterState {
  return {
    ...filters,
    types: plan.server.artifactTypes ? [] : filters.types,
    ext: plan.server.extension ? [] : filters.ext,
    path: plan.server.path && filters.path === plan.server.path ? "" : filters.path,
    columns: plan.clientColumns,
    flags: plan.server.flags ? [] : filters.flags,
    flagGrade: plan.server.flagGrade || plan.server.flags ? undefined : filters.flagGrade,
    fields: plan.server.fields ? undefined : filters.fields,
    ...(plan.server.conditions
      ? {
          from: undefined,
          to: undefined,
          weekdays: undefined,
          hours: undefined,
          offhours: undefined,
          partial: undefined,
          content: undefined,
          geo: plan.server.conditions.geo ? undefined : filters.geo,
        }
      : {}),
  };
}

/** Fold the filters into a query (server fields; paging untouched). */
export function applyFiltersToQuery(
  query: CollectionQuery,
  filters: FilterState,
  knownTypes: readonly string[] = [],
  tz = "utc",
): CollectionQuery {
  const plan = partitionFilters(query.ref, filters, knownTypes, tz);
  const next: CollectionQuery = { ...query };
  if (filters.from || filters.to) {
    // Never a reversed range (시작 > 종료): the pair is applied in order.
    const range = orderedRange(filters.from, filters.to);
    next.timeRange = { from: range.from, to: range.to };
  }
  if (filters.statuses.length) next.reviewStatus = filters.statuses;
  if (filters.tags.length) next.tags = filters.tags;
  if (plan.server.artifactTypes) next.artifactTypes = plan.server.artifactTypes;
  if (plan.server.channels) next.channels = plan.server.channels;
  if (plan.server.channelGroups) next.channelGroups = plan.server.channelGroups;
  if (plan.server.path) next.pathContains = plan.server.path;
  if (plan.server.extension) next.extension = plan.server.extension;
  if (plan.server.flags) next.flags = plan.server.flags;
  if (plan.server.flagGrade) next.flagGrade = plan.server.flagGrade;
  if (plan.server.fields) next.fields = plan.server.fields;
  if (plan.server.details) next.detailFilters = plan.server.details;
  // A view may ask for its own row condition (지도: every located row, `geo=` world box); the bar wins.
  if (plan.server.conditions) next.rowConditions = { ...query.rowConditions, ...plan.server.conditions };
  return next;
}

// --- client predicate --------------------------------------------------------

export function rowExtension(row: GridRow): string {
  const field = row.fields.extension;
  if (typeof field === "string" && field) return normalizeExt(field);
  const name = row.sourcePath ?? row.title;
  const match = /\.([A-Za-z0-9]{1,8})$/.exec(name);
  return match?.[1] ? match[1].toLowerCase() : "";
}

function rowKind(row: GridRow): string {
  const kind = row.fields.kind;
  return typeof kind === "string" ? kind : "";
}

/**
 * True when the row passes every active filter. Pass `clientOnlyFilters(…)` for a listing whose
 * API applied some of them (the row conditions are evaluated in `tz`, the display timezone).
 */
export function rowMatchesFilters(row: GridRow, filters: FilterState, tz = "utc"): boolean {
  // `[from, until)`: in order, `to` covering the whole minute / second / day it names (server rule).
  const { from, until } = timeWindow(filters.from, filters.to);
  if (from !== null || until !== null) {
    const at = parseInstant(row.timestamp)?.getTime() ?? null;
    if (at === null) return false;
    if (from !== null && at < from) return false;
    if (until !== null && at >= until) return false;
  }
  if (filters.statuses.length) {
    const ok = filters.statuses.some((s) =>
      s === "include-in-report" ? row.fields.includeInReport === true : row.reviewStatus === s,
    );
    if (!ok) return false;
  }
  if (filters.types.length) {
    const type = (row.artifactType ?? "").toLowerCase();
    const kind = rowKind(row).toLowerCase();
    if (!filters.types.some((t) => t.toLowerCase() === type || t.toLowerCase() === kind)) return false;
  }
  if (filters.tags.length && !filters.tags.some((t) => row.tags.includes(t))) return false;
  if (filters.notes && !(typeof row.fields.note === "string" && row.fields.note.trim() !== "")) return false;
  if (filters.ext.length && !filters.ext.includes(rowExtension(row))) return false;
  if (filters.path && !(row.sourcePath ?? "").toLowerCase().includes(filters.path.toLowerCase()))
    return false;
  if (!rowMatchesFlagFilter(row, filters.flags ?? [], filters.flagGrade)) return false;
  return rowMatchesConditions(row, filters, tz);
}

export function applyClientFilters(rows: GridRow[], filters: FilterState, tz = "utc"): GridRow[] {
  return hasActiveFilters(filters) ? rows.filter((row) => rowMatchesFilters(row, filters, tz)) : rows;
}

// --- chips -------------------------------------------------------------------

export type FilterKey =
  | "range"
  | "status"
  | "type"
  | "tag"
  | "ext"
  | "path"
  | "note"
  | "flag"
  | "flagGrade"
  | "field"
  | "column"
  | "clock"
  | "partial"
  | "content"
  | "geo";

export interface FilterChip {
  key: FilterKey;
  /** Item inside a multi-value filter (undefined for range/path). */
  value?: string;
  label: string;
}

/** Korean names of the event-log channel groups (core/eventlog_channels.py GROUP_LABELS). */
export const CHANNEL_GROUP_LABELS: Readonly<Record<string, string>> = {
  security: "보안",
  system: "시스템",
  application: "응용 프로그램",
  powershell: "PowerShell",
  defender: "Windows Defender",
  firewall: "방화벽(이벤트 채널)",
  "task-scheduler": "작업 스케줄러",
  storage: "스토리지",
  "user-pnp": "사용자 PNP",
  "office-alerts": "Office Alerts",
  rdp: "원격 데스크톱",
  services: "서비스(SCM)",
  other: "기타 채널",
  none: "채널 없음",
};

/** Korean names of the ntfs-meta row sources (`details.source`, R3 §3.3). */
export const ANALYSIS_SOURCE_LABELS: Readonly<Record<string, string>> = {
  mft: "MFT",
  usn: "USN 저널",
  "timestamp-mismatch": "타임스탬프 불일치",
  "logfile-transaction": "$LogFile 트랜잭션",
  "volume-information": "NTFS 볼륨 정보",
};

/** Korean readings of the carve rows' `details.recovery_method`. */
export const RECOVERY_METHOD_LABELS: Readonly<Record<string, string>> = {
  carved: "카빙",
  parsed: "파싱됨",
  rejected: "거부됨(오탐)",
};

/**
 * Server filters that have no grid column (tree-node views: 이벤트 로그 채널, 타임스탬프 불일치,
 * 복구됨(카빙)): shown as removable chips, else they would narrow the rows invisibly.
 */
export const HIDDEN_FILTER_COLUMNS: readonly string[] = [
  CHANNEL_GROUP_FILTER_COLUMN,
  CHANNEL_FILTER_COLUMN,
  "f:source",
  "f:in_use",
  "f:signature_kind",
  "f:recovery_method",
];

export interface ChipLabelOptions {
  /** Channel group id → Korean label (`/tree` `channel_groups[].label`); CHANNEL_GROUP_LABELS otherwise. */
  channelGroupLabels?: Readonly<Record<string, string>>;
}

function listText(names: string[], unit: string): string {
  return names.length > 3
    ? `${names.slice(0, 2).join(", ")} 외 ${names.length - 2}개 ${unit}`.trim()
    : names.join(", ");
}

/** Chip label of a hidden server filter (HIDDEN_FILTER_COLUMNS); null for any other column. */
export function hiddenFilterLabel(filter: ColumnFilter, options: ChipLabelOptions = {}): string | null {
  const commaValues = filter.value
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  switch (filter.col) {
    case CHANNEL_GROUP_FILTER_COLUMN: {
      const names = parseChannelFilterValue(filter.value).map(
        (id) => options.channelGroupLabels?.[id] ?? CHANNEL_GROUP_LABELS[id] ?? id,
      );
      return `채널 ${listText(names, "그룹")}`;
    }
    case CHANNEL_FILTER_COLUMN:
      return `채널 ${listText(parseChannelFilterValue(filter.value), "채널")}`;
    case "f:source":
      return `출처 ${commaValues.map((value) => ANALYSIS_SOURCE_LABELS[value] ?? value).join("·")}`;
    case "f:in_use":
      return filter.value.trim() === "true"
        ? "사용 중인 레코드"
        : filter.value.trim() === "false"
          ? "삭제된 레코드"
          : `사용 중 ${filter.value}`;
    case "f:signature_kind":
      return `서명 종류 ${listText(
        commaValues.map((value) => CARVE_KINDS.find((choice) => choice.id === value)?.label ?? value),
        "종류",
      )}`;
    case "f:recovery_method":
      return `복구 방법 ${commaValues.map((value) => RECOVERY_METHOD_LABELS[value] ?? value).join("·")}`;
    default:
      return null;
  }
}

function columnFilterId(filter: ColumnFilter): string {
  return `${filter.col}${filter.op}${filter.value}`;
}

export function activeChips(
  filters: FilterState,
  statusLabel: (s: ReviewStatus) => string,
  options: ChipLabelOptions = {},
): FilterChip[] {
  const chips: FilterChip[] = [];
  if (filters.from || filters.to) {
    chips.push({
      key: "range",
      label: `시간 ${filters.from ? filters.from.replace("T", " ") : "…"} ~ ${filters.to ? filters.to.replace("T", " ") : "…"}`,
    });
  }
  for (const s of filters.statuses) chips.push({ key: "status", value: s, label: `상태 ${statusLabel(s)}` });
  // The type's Korean name (R7 L3, C-D9); the raw id stays the chip value.
  for (const t of filters.types)
    chips.push({ key: "type", value: t, label: `유형 ${chipTypeLabel(t) ?? t}` });
  for (const t of filters.tags) chips.push({ key: "tag", value: t, label: `태그 ${t}` });
  for (const e of filters.ext) chips.push({ key: "ext", value: e, label: `확장자 .${e}` });
  if (filters.path) chips.push({ key: "path", label: `경로 ${filters.path}` });
  if (filters.notes) chips.push({ key: "note", label: "메모 있음" });
  if (filters.flagGrade) chips.push({ key: "flagGrade", label: `특이사항 ${filters.flagGrade} 이상` });
  for (const id of filters.flags ?? [])
    chips.push({ key: "flag", value: id, label: `특이사항 ${ruleLabel(id)}` });
  for (const field of RECORD_FIELD_KEYS) {
    for (const value of filters.fields?.[field] ?? []) {
      chips.push({
        key: "field",
        value: `${field}:${value}`,
        label: `${RECORD_FIELD_LABELS[field]} ${value}`,
      });
    }
  }
  for (const filter of filters.columns ?? []) {
    if (!HIDDEN_FILTER_COLUMNS.includes(filter.col)) continue;
    const label = hiddenFilterLabel(filter, options);
    if (label) chips.push({ key: "column", value: columnFilterId(filter), label });
  }
  if (hasClock(filters)) chips.push({ key: "clock", label: clockLabel(filters) });
  if (filters.partial) chips.push({ key: "partial", label: "부분 결과만" });
  for (const id of filters.content ?? [])
    chips.push({ key: "content", value: id, label: `콘텐츠 ${contentTypeLabel(id)}` });
  const box = parseGeo(filters.geo);
  if (box) {
    const lat = ((box[0] + box[2]) / 2).toFixed(3);
    const lon = ((box[1] + box[3]) / 2).toFixed(3);
    chips.push({ key: "geo", label: `위치 ${lat}, ${lon} 부근` });
  }
  return chips;
}

export function removeChip(filters: FilterState, chip: FilterChip): FilterState {
  switch (chip.key) {
    case "range":
      return { ...filters, from: undefined, to: undefined };
    case "status":
      return { ...filters, statuses: filters.statuses.filter((s) => s !== chip.value) };
    case "type":
      return { ...filters, types: filters.types.filter((t) => t !== chip.value) };
    case "tag":
      return { ...filters, tags: filters.tags.filter((t) => t !== chip.value) };
    case "ext":
      return { ...filters, ext: filters.ext.filter((e) => e !== chip.value) };
    case "path":
      return { ...filters, path: "" };
    case "note":
      return { ...filters, notes: false };
    case "flag":
      return { ...filters, flags: (filters.flags ?? []).filter((id) => id !== chip.value) };
    case "flagGrade":
      return { ...filters, flagGrade: undefined };
    case "field": {
      const at = (chip.value ?? "").indexOf(":");
      const field = (chip.value ?? "").slice(0, at) as RecordFieldKey;
      const value = (chip.value ?? "").slice(at + 1);
      const rest = (filters.fields?.[field] ?? []).filter((item) => item !== value);
      const fields: RecordFieldFilters = { ...filters.fields, [field]: rest.length ? rest : undefined };
      if (!rest.length) delete fields[field];
      return { ...filters, fields: hasRecordFields(fields) ? fields : undefined };
    }
    case "column":
      return {
        ...filters,
        columns: (filters.columns ?? []).filter((filter) => columnFilterId(filter) !== chip.value),
      };
    case "clock":
      return { ...filters, weekdays: undefined, hours: undefined, offhours: undefined };
    case "partial":
      return { ...filters, partial: undefined };
    case "content": {
      const rest = (filters.content ?? []).filter((id) => id !== chip.value);
      return { ...filters, content: rest.length ? rest : undefined };
    }
    case "geo":
      return { ...filters, geo: undefined };
  }
}
