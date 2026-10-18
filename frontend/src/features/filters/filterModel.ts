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
 *  - timeline/files/docs/indicators: paging only, nothing server-side
 * Everything else (time range, review status, tags, other column filters) runs on
 * the rows already loaded; the filter status line says so.
 */

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
import { type Grade, isGrade } from "../flags/catalog";
import { rowMatchesFlagFilter, ruleLabel } from "../flags/flags";

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
}

export const EMPTY_FILTERS: FilterState = Object.freeze({
  statuses: [],
  types: [],
  tags: [],
  ext: [],
  path: "",
  columns: [],
}) as FilterState;

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
    columnsKey(a.columns) === columnsKey(b.columns)
  );
}

export function hasActiveFilters(filters: FilterState): boolean {
  return !filtersEqual(filters, EMPTY_FILTERS);
}

// --- time presets -----------------------------------------------------------

export type TimePreset = "today" | "7d" | "30d";

export const TIME_PRESET_LABELS: Record<TimePreset, string> = {
  today: "오늘",
  "7d": "7일",
  "30d": "30일",
};

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
  else start.setTime(now.getTime() - (preset === "7d" ? 7 : 30) * 86_400_000);
  return { from: toLocalInput(start), to: toLocalInput(now) };
}

/** Which preset (if any) the current range equals, with a minute of slack. */
export function activePreset(filters: FilterState, now: Date = new Date()): TimePreset | null {
  if (!filters.from || !filters.to) return null;
  for (const preset of ["today", "7d", "30d"] as const) {
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
): FilterPlan {
  const server: FilterPlan["server"] = {};
  const serverLabels: string[] = [];
  const clientLabels: string[] = [];
  const clientColumns: ColumnFilter[] = [];
  const serverColumns: ColumnFilter[] = [];
  const pathOnServer = ref.id === "artifacts" || ref.id === "analysis";
  let typeColumn: "exact" | "contains" | null = null;

  if (filters.from || filters.to) clientLabels.push("시간 범위"); // no from/to on any API
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
  };
}

/** Fold the filters into a query (server fields; paging untouched). */
export function applyFiltersToQuery(
  query: CollectionQuery,
  filters: FilterState,
  knownTypes: readonly string[] = [],
): CollectionQuery {
  const plan = partitionFilters(query.ref, filters, knownTypes);
  const next: CollectionQuery = { ...query };
  if (filters.from || filters.to) next.timeRange = { from: filters.from, to: filters.to };
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
  return next;
}

// --- client predicate --------------------------------------------------------

function parseTime(value: string | undefined | null): number | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

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

/** True when the row passes every active filter (server-handled ones are re-checked; harmless). */
export function rowMatchesFilters(row: GridRow, filters: FilterState): boolean {
  const from = parseTime(filters.from);
  const to = parseTime(filters.to);
  if (from !== null || to !== null) {
    const at = parseInstant(row.timestamp)?.getTime() ?? null;
    if (at === null) return false;
    if (from !== null && at < from) return false;
    if (to !== null && at > to) return false;
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
  return true;
}

export function applyClientFilters(rows: GridRow[], filters: FilterState): GridRow[] {
  return hasActiveFilters(filters) ? rows.filter((row) => rowMatchesFilters(row, filters)) : rows;
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
  | "field";

export interface FilterChip {
  key: FilterKey;
  /** Item inside a multi-value filter (undefined for range/path). */
  value?: string;
  label: string;
}

export function activeChips(filters: FilterState, statusLabel: (s: ReviewStatus) => string): FilterChip[] {
  const chips: FilterChip[] = [];
  if (filters.from || filters.to) {
    chips.push({
      key: "range",
      label: `시간 ${filters.from ? filters.from.replace("T", " ") : "…"} ~ ${filters.to ? filters.to.replace("T", " ") : "…"}`,
    });
  }
  for (const s of filters.statuses) chips.push({ key: "status", value: s, label: `상태 ${statusLabel(s)}` });
  for (const t of filters.types) chips.push({ key: "type", value: t, label: `유형 ${t}` });
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
  }
}
