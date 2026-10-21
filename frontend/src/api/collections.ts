// Collection fetchers for the single DataGrid (console-redesign S3).
//
// Each fetcher returns a RawPage: raw API rows plus the paging/backend facts the
// grid footer shows. Mapping raw rows to GridRow lives in
// features/grid/columns/<collection>.ts so the API layer stays shape-agnostic.

import {
  type CollectionQuery,
  hasRecordFields,
  type RecordFieldFilters,
  type ServerSort,
  type ServerSortState,
} from "../contracts/collection";
import { ApiError, api } from "./client";
import { type ArtifactsQuery, artifactsQueryString } from "./runs";

export type RawRow = Record<string, unknown>;

export interface RawPage {
  rows: RawRow[];
  /** null when the backend cannot tell (never for the paged JSON outputs). */
  total: number | null;
  offset: number;
  backend: string;
  truncated: boolean;
  elapsedMs: number;
  /** More rows exist after this page (needed when `total` is null). */
  hasMore?: boolean;
  /** Rows scanned by a server-side filter. */
  scanned?: number;
  /** Artifact kinds the page was drawn from when a category restricted them (category nodes). */
  kinds?: string[];
  /** Server sort state of a sorted artifacts page (building pages have no rows yet). */
  sort?: ServerSortState;
  /** Page-level facts beyond paging (files: `ntfs_join`, plan analysis-workbench-p1 §3.3). */
  meta?: Record<string, unknown>;
}

const enc = encodeURIComponent;

/**
 * 특이사항 filter of a listing (`flag=` repeated, `flag_grade=`) plus the artifacts' exact
 * record-field filters (`browser=` / `service=`, r2 console fix M2) — both server-side row
 * filters that page across kinds the same way.
 */
export interface FlagFilter {
  ids?: readonly string[];
  grade?: string;
  fields?: RecordFieldFilters;
  /** Row conditions (r4 §2.3) the listing API applies: query params, lists repeat. */
  conditions?: Record<string, string | string[]>;
}

function hasConditions(filter: FlagFilter | undefined): boolean {
  return Boolean(filter?.conditions && Object.keys(filter.conditions).length);
}

function flagQuery(filter: FlagFilter | undefined): {
  flag?: string[];
  flag_grade?: string;
  browser?: string[];
  service?: string[];
  conditions?: Record<string, string | string[]>;
} {
  return {
    ...(filter?.ids?.length ? { flag: [...filter.ids] } : {}),
    ...(filter?.grade ? { flag_grade: filter.grade } : {}),
    ...(filter?.fields?.browser?.length ? { browser: [...filter.fields.browser] } : {}),
    ...(filter?.fields?.service?.length ? { service: [...filter.fields.service] } : {}),
    ...(hasConditions(filter) ? { conditions: filter?.conditions } : {}),
  };
}

/** Event-log channel filter of a listing: exact names (`channel=`) and/or group ids (`channel_group=`). */
export interface ChannelQuery {
  names?: readonly string[];
  groups?: readonly string[];
}

function channelParams(query: ChannelQuery | undefined): { channel?: string[]; channel_group?: string[] } {
  return {
    ...(query?.names?.length ? { channel: [...query.names] } : {}),
    ...(query?.groups?.length ? { channel_group: [...query.groups] } : {}),
  };
}

function hasChannelQuery(query: ChannelQuery | undefined): boolean {
  return Boolean(query?.names?.length || query?.groups?.length);
}

function hasFlagFilter(filter: FlagFilter | undefined): boolean {
  return Boolean(
    filter?.ids?.length || filter?.grade || hasRecordFields(filter?.fields) || hasConditions(filter),
  );
}

/** `&flag=…&flag_grade=…` (+ row conditions) for the JSON listings (files, analysis, timeline). */
export function flagQueryString(filter: FlagFilter | undefined): string {
  const params = new URLSearchParams();
  for (const id of filter?.ids ?? []) params.append("flag", id);
  if (filter?.grade) params.set("flag_grade", filter.grade);
  for (const [key, value] of Object.entries(filter?.conditions ?? {})) {
    for (const item of Array.isArray(value) ? value : [value]) params.append(key, item);
  }
  const text = params.toString();
  return text ? `&${text}` : "";
}

function now(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

function asRows(value: unknown): RawRow[] {
  return Array.isArray(value) ? (value as RawRow[]) : [];
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

async function jsonPaged(
  runId: string,
  endpoint: "files" | "docs" | "timeline" | "indicators",
  key: string,
  offset: number,
  limit: number,
  signal?: AbortSignal,
  category?: string,
  scope?: string,
  extra = "",
  /** The server filtered the rows (folder, flags, row conditions): `matched` is the total, like a category page. */
  serverFiltered = false,
): Promise<RawPage> {
  const started = now();
  const filter = `${scope ? `&scope=${enc(scope)}` : ""}${category ? `&category=${enc(category)}` : ""}${extra}`;
  const payload = await api<Record<string, unknown>>(
    `/api/runs/${enc(runId)}/${endpoint}?offset=${offset}&limit=${limit}${filter}`,
    { signal },
  );
  // `scope=inventory` pages may name their list `inventory` or keep `candidates`.
  const rows = asRows(
    key === "inventory" && !Array.isArray(payload.inventory) ? payload.candidates : payload[key],
  );
  const meta: Record<string, unknown> = {};
  // Files rows are joined with the newest NTFS-meta analysis; `null` = never ran (absent = old server).
  if ("ntfs_join" in payload) meta.ntfs_join = payload.ntfs_join;
  // Timeline pages: the acquisition root the event paths start with (출처 행 column strips it).
  if (endpoint === "timeline" && typeof payload.root === "string") meta.root = payload.root;
  // Files pages (parser-quality r2): candidates vs. every scanned file (`scope=inventory`).
  for (const key of ["scope", "inventory_count", "candidate_count"] as const) {
    if (key in payload) meta[key] = payload[key];
  }
  const base = {
    rows,
    offset,
    backend: "file",
    elapsedMs: Math.round(now() - started),
    ...(Object.keys(meta).length ? { meta } : {}),
  };
  const pagination =
    payload.pagination && typeof payload.pagination === "object" && !Array.isArray(payload.pagination)
      ? (payload.pagination as Record<string, unknown>)
      : {};
  if ((category || serverFiltered) && ("matched" in payload || "truncated" in pagination)) {
    // A category-filtered files page (artifact_filter.filter_files_by_category) counts its
    // matches: `matched` is exact, or null when the scan hit its cap (`pagination.truncated`).
    // Its top-level `total` is the copied UNFILTERED payload total — never show that.
    const truncated = pagination.truncated === true;
    const matched = truncated ? null : (asNumber(payload.matched) ?? asNumber(pagination.matched));
    const scanned = asNumber(pagination.scanned);
    return {
      ...base,
      total: matched,
      truncated,
      hasMore: pagination.has_more === true || payload.has_more === true,
      ...(scanned !== null ? { scanned } : {}),
    };
  }
  // paginate_payload (api/app/pagination.py) puts the collection size in `pagination.total`;
  // the outputs themselves (files, indicators) carry no top-level `total`. Falling back to the
  // page length capped the grid at one page ("총 250건") while the tree counted thousands.
  const total = asNumber(pagination.total) ?? asNumber(payload.total) ?? asNumber(payload.record_count);
  const hasMore =
    pagination.has_more === true ||
    payload.has_more === true ||
    (total !== null && offset + rows.length < total);
  if (total === null) {
    // No count at all (very old server): page on while full pages keep coming.
    const more = hasMore || rows.length >= limit;
    return { ...base, total: more ? null : offset + rows.length, truncated: false, hasMore: more };
  }
  return { ...base, total, truncated: false, hasMore };
}

/** 파일 시스템 탐색기 filter of `GET /files`: one fs-tree folder (`path_prefix=`) or special node. */
export interface FilesPathFilter {
  /** Folder relative to the volume root (`""` = root); undefined = no folder filter. */
  dir?: string;
  /** The folder's whole subtree (`recursive=1`) instead of its direct files. */
  recursive?: boolean;
  /** fs-tree special node (`special=orphan|unallocated|slack`). */
  special?: string;
}

/** `&path_prefix=…&recursive=1&special=…` for `GET /files` ("" when no folder filter). */
export function filesPathQueryString(filter: FilesPathFilter | undefined): string {
  const params = new URLSearchParams();
  if (filter?.dir !== undefined) {
    params.set("path_prefix", filter.dir);
    if (filter.recursive) params.set("recursive", "1");
  }
  if (filter?.special) params.set("special", filter.special);
  const text = params.toString();
  return text ? `&${text}` : "";
}

/** `GET /files` (optionally `category=<id>`: documents, images, archives, databases, emails, …). */
export const fetchFilesPage = (
  runId: string,
  offset: number,
  limit: number,
  signal?: AbortSignal,
  category?: string,
  flags?: FlagFilter,
  path?: FilesPathFilter,
) => {
  const route = parseFilesCategory(category);
  const pathQuery = filesPathQueryString(path);
  return jsonPaged(
    runId,
    "files",
    route.rowsKey,
    offset,
    limit,
    signal,
    route.category,
    route.scope,
    flagQueryString(flags) + pathQuery,
    // Folder, 특이사항 and row-condition pages count matches (`matched`, null past the scan cap).
    Boolean(pathQuery) || Boolean(flags?.ids?.length || flags?.grade) || hasConditions(flags),
  );
};

/**
 * Route `category=` value of the files inventory (parser-quality r2): `inventory` = every scanned
 * file (`GET /files?scope=inventory`), `inventory:<id>` = one category of it (`other` = files
 * outside the selected scan categories). Any other value is a candidates category.
 */
export const FILES_INVENTORY = "inventory";

export function filesInventoryCategory(category?: string): string {
  return category ? `${FILES_INVENTORY}:${category}` : FILES_INVENTORY;
}

export interface FilesRouteCategory {
  /** `scope=` sent to `/files`; undefined = the default candidates scope. */
  scope?: "inventory";
  /** `category=` sent to `/files`. */
  category?: string;
  /** Response list holding the rows. */
  rowsKey: "candidates" | "inventory";
}

export function parseFilesCategory(value: string | undefined): FilesRouteCategory {
  if (!value) return { rowsKey: "candidates" };
  if (value === FILES_INVENTORY) return { scope: "inventory", rowsKey: "inventory" };
  if (value.startsWith(`${FILES_INVENTORY}:`)) {
    const category = value.slice(FILES_INVENTORY.length + 1);
    return { scope: "inventory", rowsKey: "inventory", ...(category ? { category } : {}) };
  }
  return { category: value, rowsKey: "candidates" };
}
/**
 * Which list a `/docs` page holds. The paged collection names itself (`pagination.collection`);
 * servers that page `results` still carry `candidates` as an EMPTY list (`omitted_fields`), so a
 * mere array is not enough to pick it.
 */
export function docsRowsKey(
  payload: Record<string, unknown>,
  pagination: Record<string, unknown>,
): "candidates" | "results" {
  if (pagination.collection === "candidates" || pagination.collection === "results")
    return pagination.collection;
  const omitted = Array.isArray(payload.omitted_fields) ? payload.omitted_fields : [];
  if (omitted.includes("candidates")) return "results";
  if (Array.isArray(payload.candidates) && payload.candidates.length > 0) return "candidates";
  return Array.isArray(payload.results) ? "results" : "candidates";
}

/** Docs route value of the "일치만" toggle (`#/case/{run}/explore/docs?category=matched`). */
export const DOCS_MATCHED = "matched";
/** Docs route value for the non-matching documents (`all=1&matched=0`). */
export const DOCS_UNMATCHED = "unmatched";

/** Which `/docs` list is requested: every document, the keyword matches only, or the non-matches. */
export type DocsView = "all" | "matched" | "unmatched";

/** Query suffix per view: `all=1` pages `candidates`; plain `/docs` pages `results` (matches). */
export function docsViewQuery(view: DocsView): string {
  if (view === "matched") return "";
  return view === "unmatched" ? "&all=1&matched=0" : "&all=1";
}

/**
 * `GET /docs`: every document candidate (`all=1` pages `candidates`), the non-matches
 * (`all=1&matched=0`), or only the keyword matches (plain request, pages `results`). A server that still pages only `results` (the matches) is read as
 * before; `meta.docs_rows` says which list the rows came from ("candidates" | "results").
 */
export async function fetchDocsPage(
  runId: string,
  offset: number,
  limit: number,
  signal?: AbortSignal,
  view: DocsView = "all",
): Promise<RawPage> {
  const started = now();
  const payload = await api<Record<string, unknown>>(
    `/api/runs/${enc(runId)}/docs?offset=${offset}&limit=${limit}${docsViewQuery(view)}`,
    { signal },
  );
  const pagination =
    payload.pagination && typeof payload.pagination === "object" && !Array.isArray(payload.pagination)
      ? (payload.pagination as Record<string, unknown>)
      : {};
  const key = docsRowsKey(payload, pagination);
  const rows = asRows(payload[key]);
  const total =
    (view === "matched"
      ? (asNumber(payload.matched_count) ?? asNumber(payload.matched) ?? asNumber(pagination.matched))
      : null) ??
    asNumber(pagination.total) ??
    asNumber(payload.total) ??
    asNumber(payload.record_count);
  const hasMore =
    pagination.has_more === true ||
    payload.has_more === true ||
    (total !== null ? offset + rows.length < total : rows.length >= limit);
  return {
    rows,
    offset,
    backend: "file",
    elapsedMs: Math.round(now() - started),
    total: total ?? (hasMore ? null : offset + rows.length),
    truncated: pagination.truncated === true,
    hasMore,
    meta: { docs_rows: key },
  };
}
/**
 * Timeline page. `search.q` is the server text search (`q=`: summary, target, path, event type,
 * Korean event name — every event, not the loaded page); `search.group` asks for display groups
 * (`group=1`: one row per target · second · kind family, with `source_count` / `sources`).
 */
export const fetchTimelinePage = (
  runId: string,
  offset: number,
  limit: number,
  signal?: AbortSignal,
  conditions?: Record<string, string | string[]>,
  search: { q?: string; group?: boolean } = {},
) => {
  const q = search.q?.trim() ?? "";
  const extra = `${flagQueryString({ conditions })}${q ? `&q=${enc(q)}` : ""}${search.group ? "&group=1" : ""}`;
  return jsonPaged(
    runId,
    "timeline",
    "events",
    offset,
    limit,
    signal,
    undefined,
    undefined,
    extra,
    Object.keys(conditions ?? {}).length > 0 || q !== "" || search.group === true,
  );
};
export const fetchIndicatorsPage = (runId: string, offset: number, limit: number, signal?: AbortSignal) =>
  jsonPaged(runId, "indicators", "indicators", offset, limit, signal);

interface ArtifactKindPage {
  artifacts?: unknown;
  total?: unknown;
  record_count?: unknown;
  has_more?: unknown;
  pagination?: {
    has_more?: unknown;
    scanned?: unknown;
    truncated?: unknown;
    filtered?: unknown;
    matched?: unknown;
  };
  sort?: unknown;
  sort_supported?: unknown;
  /** Filtered count of the kind (null while the filter scan stopped early). */
  matched?: unknown;
}

/** `cross_kind` block of a typed request over 0 / 2+ kinds (cursor paging, `after=`). */
interface CrossKindBlock {
  kinds?: unknown;
  order?: unknown;
  record_count?: unknown;
  matched?: unknown;
  has_more?: unknown;
  next_offset?: unknown;
  next_after?: unknown;
  scanned?: unknown;
  truncated?: unknown;
  /**
   * `geo=` listings (r6 §3.3 갈래 C): `true` = paged from the run's located-row index; otherwise
   * why not (`building` / `truncated` / `unavailable`: the rows come from a capped scan).
   */
  geo_index?: unknown;
}

/** `after=` cursors per filtered cross-kind listing: offset → cursor that resumes there. */
const crossKindCursors = new Map<string, Map<number, string>>();

export function resetCrossKindCursors(): void {
  crossKindCursors.clear();
}

async function crossKindRequest(
  runId: string,
  query: ArtifactsQuery & { after?: string },
  signal?: AbortSignal,
): Promise<{ artifacts?: Record<string, ArtifactKindPage>; cross_kind?: CrossKindBlock }> {
  const params = new URLSearchParams(
    artifactsQueryString({ ...query, offset: query.after ? undefined : query.offset || undefined }),
  );
  if (query.after) params.set("after", query.after);
  return api(`/api/runs/${enc(runId)}/artifacts?${params}`, { signal });
}

/** Requests per page while short / truncated windows are followed (scan cap per request). */
export const CROSS_KIND_MAX_REQUESTS = 200;
const CROSS_KIND_MAX_LIMIT = 1000;

/** Matches consumed before the cursor: the `<matched>` of `<kind>:<record_index>:<matched>`. */
function cursorPosition(after: string): number | null {
  const tail = after.slice(after.lastIndexOf(":") + 1);
  return /^\d+$/.test(tail) ? Number(tail) : null;
}

/**
 * One page of a type-filtered listing across kinds (all kinds, or a category's kinds): the
 * server pages the matches as one collection (`cross_kind`). The page starts at the nearest
 * stored cursor at or before `offset` and follows `next_after` — never an offset rescan —
 * through short or truncated windows (a scan-capped window may return 0 rows) until it holds
 * `limit` rows or the scan is exhausted. Rows are exactly the matches at positions
 * [offset, offset + rows.length).
 */
async function fetchCrossKindPage(
  runId: string,
  kinds: string[] | undefined,
  offset: number,
  limit: number,
  signal: AbortSignal | undefined,
  filter: string | undefined,
  types: string[],
  started: number,
  flags?: FlagFilter,
  channels?: ChannelQuery,
): Promise<RawPage> {
  const fl = { ...flagQuery(flags), ...channelParams(channels) };
  if (kinds?.length === 1) {
    // One kind: the ordinary kind page (offset paging, `matched`).
    const kind = kinds[0] as string;
    const window = await artifactWindow(
      runId,
      { kind: [kind], offset, limit, path_contains: filter, artifact_type: types, ...fl },
      signal,
    );
    const page = window[kind] ?? {};
    return {
      rows: asRows(page.artifacts).map((row, i) => withLocator(row, kind, offset + i)),
      total: kindTotal(page),
      offset,
      backend: "file",
      ...pageFlags([page]),
      elapsedMs: Math.round(now() - started),
      kinds,
    };
  }
  const key = JSON.stringify([runId, kinds ?? null, filter ?? "", [...types].sort(), fl]);
  const cursors = crossKindCursors.get(key) ?? new Map<number, string>();
  crossKindCursors.set(key, cursors);
  let pos = 0;
  let after: string | undefined;
  for (const [known, cursor] of cursors) {
    if (known <= offset && known >= pos) {
      pos = known;
      after = cursor;
    }
  }
  const rows: RawRow[] = [];
  let scanned = 0;
  let truncated = false;
  let exhausted = false;
  let matched: number | null = null;
  let geoIndex: string | undefined;
  for (let request = 0; request < CROSS_KIND_MAX_REQUESTS; request += 1) {
    const want = Math.min(CROSS_KIND_MAX_LIMIT, Math.max(1, offset - pos + (limit - rows.length)));
    const payload = await crossKindRequest(
      runId,
      { kind: kinds, offset: 0, limit: want, path_contains: filter, artifact_type: types, after, ...fl },
      signal,
    );
    const cross = payload.cross_kind ?? {};
    if (typeof cross.geo_index === "string") geoIndex = cross.geo_index;
    const window = payload.artifacts ?? {};
    const byKind = new Map<string, Map<number, RawRow>>();
    for (const [k, page] of Object.entries(window)) {
      const index = new Map<number, RawRow>();
      for (const row of asRows(page.artifacts)) {
        if (typeof row.record_index === "number") index.set(row.record_index, row);
      }
      byKind.set(k, index);
    }
    const order = Array.isArray(cross.order) ? cross.order : [];
    order.forEach((entry, i) => {
      if (!Array.isArray(entry)) return;
      const [k, recordIndex] = entry as [unknown, unknown];
      if (typeof k !== "string" || typeof recordIndex !== "number") return;
      const position = pos + i;
      const row = byKind.get(k)?.get(recordIndex);
      if (row && position >= offset && rows.length < limit) rows.push(withLocator(row, k, recordIndex));
    });
    scanned += asNumber(cross.scanned) ?? 0;
    truncated = cross.truncated === true;
    const nextAfter = typeof cross.next_after === "string" && cross.next_after ? cross.next_after : null;
    const nextPos = (nextAfter ? cursorPosition(nextAfter) : null) ?? pos + order.length;
    if (nextAfter) cursors.set(nextPos, nextAfter);
    pos = nextPos;
    after = nextAfter ?? undefined;
    if (!nextAfter) {
      exhausted = true;
      matched = asNumber(cross.matched) ?? pos;
      break;
    }
    if (rows.length >= limit) break;
  }
  return {
    rows,
    // The filtered count once the scan reached the end; otherwise unknown (paging continues).
    total: exhausted ? matched : null,
    offset,
    backend: "file",
    hasMore: !exhausted,
    truncated: !exhausted && rows.length < limit,
    scanned: scanned || undefined,
    elapsedMs: Math.round(now() - started),
    meta: {
      matched: exhausted ? matched : null,
      crossKind: true,
      ...(truncated ? { lastWindowTruncated: true } : {}),
      ...(geoIndex ? { geoIndex } : {}),
    },
    ...(kinds ? { kinds } : {}),
  };
}

/** Row locator index: the server's original JSONL `record_index` when present, else the page position. */
function withLocator(row: RawRow, kind: string, fallback: number): RawRow {
  const index =
    typeof row.record_index === "number" && Number.isInteger(row.record_index) && row.record_index >= 0
      ? row.record_index
      : fallback;
  return { ...row, _kind: kind, _index: index };
}

export const SORT_UNSUPPORTED_REASON = "서버가 이 열의 전체 정렬을 지원하지 않습니다.";

/** Normalise a kind's `sort` object; a missing one with `sort_supported: false` means unsupported. */
export function sortStateOf(page: ArtifactKindPage, requested: ServerSort): ServerSortState {
  const raw = page.sort;
  if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    const status =
      obj.status === "building" || obj.status === "unsupported" || obj.status === "ready"
        ? obj.status
        : "ready";
    const progress = asNumber(obj.progress);
    return {
      key: typeof obj.key === "string" ? obj.key : requested.key,
      order: obj.order === "desc" || obj.order === "asc" ? obj.order : requested.order,
      status,
      progress: progress === null ? (status === "ready" ? 1 : 0) : Math.max(0, Math.min(1, progress)),
      ...(typeof obj.reason === "string" && obj.reason ? { reason: obj.reason } : {}),
    };
  }
  if (page.sort_supported === false) {
    return { ...requested, status: "unsupported", progress: 0, reason: SORT_UNSUPPORTED_REASON };
  }
  return { ...requested, status: "ready", progress: 1 };
}

/** Delay before the one automatic retry of a 409 (stale sort index: the file changed under it). */
export const STALE_RETRY_MS = 500;

function wait(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(signal.reason);
      },
      { once: true },
    );
  });
}

async function artifactWindow(
  runId: string,
  query: ArtifactsQuery,
  signal?: AbortSignal,
): Promise<Record<string, ArtifactKindPage>> {
  const url = `/api/runs/${enc(runId)}/artifacts?${artifactsQueryString({ ...query, offset: query.offset || undefined })}`;
  let payload: { artifacts?: Record<string, ArtifactKindPage> };
  try {
    payload = await api<{ artifacts?: Record<string, ArtifactKindPage> }>(url, { signal });
  } catch (error) {
    // 409 = the server's sort index went stale (file changed / rebuilt): retry once, then surface it.
    if (!(error instanceof ApiError) || error.status !== 409) throw error;
    await wait(STALE_RETRY_MS, signal);
    payload = await api<{ artifacts?: Record<string, ArtifactKindPage> }>(url, { signal });
  }
  return payload.artifacts ?? {};
}

function kindTotal(page: ArtifactKindPage): number | null {
  // A filtered page counts its matches (`matched`; null while the scan stopped early).
  if (page.pagination?.filtered === true) return asNumber(page.matched ?? page.pagination.matched);
  const direct = asNumber(page.total) ?? asNumber(page.record_count);
  if (direct !== null) return direct;
  return page.pagination?.filtered === true ? null : asRows(page.artifacts).length;
}

const countsCache = new Map<string, { at: number; counts: [string, number][] }>();
const COUNTS_TTL_MS = 30_000;

/** Per-kind record counts (sorted by kind), via a limit=1 probe; cached briefly. */
async function artifactKindCounts(runId: string, signal?: AbortSignal): Promise<[string, number][]> {
  const cached = countsCache.get(runId);
  if (cached && Date.now() - cached.at < COUNTS_TTL_MS) return cached.counts;
  const window = await artifactWindow(runId, { limit: 1 }, signal);
  const counts = Object.keys(window)
    .sort()
    .map((kind): [string, number] => [kind, kindTotal(window[kind] as ArtifactKindPage) ?? 0]);
  countsCache.set(runId, { at: Date.now(), counts });
  return counts;
}

export function resetArtifactCountsCache(): void {
  countsCache.clear();
  crossKindCursors.clear();
}

function pageFlags(pages: ArtifactKindPage[]) {
  return {
    hasMore: pages.some((p) => p.pagination?.has_more === true || p.has_more === true),
    truncated: pages.some((p) => p.pagination?.truncated === true),
    scanned: pages.reduce((sum, p) => sum + (asNumber(p.pagination?.scanned) ?? 0), 0) || undefined,
  };
}

/**
 * Sorted position (0-based) of one record (`record_index`) of a server-sorted kind:
 * `GET /artifacts?kind=&sort=&order=&locate=` → `sort.position`. Null while the index
 * is building, when the record is out of range / filtered out, or the server cannot tell.
 */
export async function locateArtifactRow(
  runId: string,
  kind: string,
  sort: ServerSort,
  recordIndex: number,
  signal?: AbortSignal,
  pathContains?: string,
): Promise<{ status: ServerSortState["status"]; position: number | null }> {
  const window = await artifactWindow(
    runId,
    {
      kind: [kind],
      offset: 0,
      limit: 1,
      path_contains: pathContains?.trim() || undefined,
      sort: sort.key,
      order: sort.order,
      locate: recordIndex,
    },
    signal,
  );
  const page = window[kind];
  if (!page) return { status: "ready", position: null };
  const state = sortStateOf(page, sort);
  const raw =
    page.sort && typeof page.sort === "object" ? (page.sort as Record<string, unknown>).position : null;
  const position = typeof raw === "number" && Number.isInteger(raw) && raw >= 0 ? raw : null;
  return { status: state.status, position: state.status === "ready" ? position : null };
}

/**
 * One window of the artifacts collection. A single kind = one `kind=` request
 * (server pages only that kind). `pathContains` is the server-side path filter:
 * offset then counts matches and `total` is null unless the kind was fully scanned.
 * Rows carry `_kind` and `_index`: the server's `record_index` (original JSONL index)
 * when present, so locators survive sorting and filtering; older servers without it
 * fall back to the page position (with a filter that is only the match ordinal).
 * `sort` (one kind only) asks the server for a whole-kind sort; the page carries the
 * sort state and has no rows while the server index is `building`.
 *
 * `restrictKinds` (category nodes, no `kind`) narrows the run's kinds — it gets
 * the run's kind list and returns the kinds to page; the page reports them in `kinds`.
 */
export async function fetchArtifactsPage(
  runId: string,
  kind: string | undefined,
  offset: number,
  limit: number,
  signal?: AbortSignal,
  pathContains?: string,
  restrictKinds?: (available: readonly string[]) => string[],
  sort?: ServerSort,
  artifactTypes?: readonly string[],
  flags?: FlagFilter,
  channelQuery?: ChannelQuery,
): Promise<RawPage> {
  const started = now();
  const filter = pathContains?.trim() || undefined;
  const types = artifactTypes?.length ? [...artifactTypes] : undefined;
  const channels = hasChannelQuery(channelQuery) ? channelQuery : undefined;
  const fl = { ...flagQuery(flags), ...channelParams(channels) };
  if (!kind && restrictKinds) {
    return fetchArtifactKindsPage(
      runId,
      restrictKinds,
      offset,
      limit,
      signal,
      filter,
      started,
      types,
      flags,
      channels,
    );
  }
  if (kind) {
    const window = await artifactWindow(
      runId,
      {
        kind: [kind],
        offset,
        limit,
        path_contains: filter,
        artifact_type: types,
        sort: sort?.key,
        order: sort?.order,
        ...fl,
      },
      signal,
    );
    const page = window[kind];
    if (!page) return { rows: [], total: 0, offset, backend: "file", truncated: false, elapsedMs: 0 };
    const sortState = sort ? sortStateOf(page, sort) : undefined;
    const rows =
      sortState?.status === "building"
        ? []
        : asRows(page.artifacts).map((row, i) => withLocator(row, kind, offset + i));
    return {
      rows,
      total: kindTotal(page),
      offset,
      backend: "file",
      ...pageFlags([page]),
      elapsedMs: Math.round(now() - started),
      ...(sortState ? { sort: sortState } : {}),
    };
  }
  // Types, channels or 특이사항 over every kind: one cross-kind listing (cursor paging).
  if (types || channels || hasFlagFilter(flags)) {
    return fetchCrossKindPage(
      runId,
      undefined,
      offset,
      limit,
      signal,
      filter,
      types ?? [],
      started,
      flags,
      channels,
    );
  }
  if (filter) {
    // All kinds + path filter: per-kind matches from the first window only.
    const window = await artifactWindow(
      runId,
      { offset: 0, limit, path_contains: filter, artifact_type: types },
      signal,
    );
    const rows: RawRow[] = [];
    for (const k of Object.keys(window).sort()) {
      for (const [i, row] of asRows(window[k]?.artifacts).entries()) rows.push(withLocator(row, k, i));
    }
    const flags = pageFlags(Object.values(window));
    return {
      rows,
      total: offset === 0 ? rows.length : null,
      offset,
      backend: "file",
      hasMore: false,
      truncated: flags.truncated || flags.hasMore,
      scanned: flags.scanned,
      elapsedMs: Math.round(now() - started),
    };
  }
  const counts = await artifactKindCounts(runId, signal);
  const { rows, total } = await pageAcrossKinds(runId, counts, offset, limit, signal);
  return { rows, total, offset, backend: "file", truncated: false, elapsedMs: Math.round(now() - started) };
}

/** Concatenate kinds in `counts` order and fetch the [offset, offset+limit) window (one `kind=` request per kind touched). */
async function pageAcrossKinds(
  runId: string,
  counts: [string, number][],
  offset: number,
  limit: number,
  signal?: AbortSignal,
): Promise<{ rows: RawRow[]; total: number }> {
  const total = counts.reduce((sum, [, n]) => sum + n, 0);
  const rows: RawRow[] = [];
  let base = 0;
  for (const [k, n] of counts) {
    const start = Math.max(offset, base);
    const end = Math.min(offset + limit, base + n);
    if (end > start) {
      const local = start - base;
      const window = await artifactWindow(runId, { kind: [k], offset: local, limit: end - start }, signal);
      for (const [i, row] of asRows(window[k]?.artifacts).entries()) {
        rows.push(withLocator(row, k, local + i));
      }
    }
    base += n;
    if (base >= offset + limit) break;
  }
  return { rows, total };
}

/** Category window: page across the kinds `restrict` keeps (one `kind=` per kind, or repeated `kind=` with a path filter). */
async function fetchArtifactKindsPage(
  runId: string,
  restrict: (available: readonly string[]) => string[],
  offset: number,
  limit: number,
  signal: AbortSignal | undefined,
  filter: string | undefined,
  started: number,
  types?: string[],
  flags?: FlagFilter,
  channels?: ChannelQuery,
): Promise<RawPage> {
  const all = await artifactKindCounts(runId, signal);
  const allowed = new Set(restrict(all.map(([k]) => k)));
  const counts = all.filter(([k]) => allowed.has(k));
  const kinds = counts.map(([k]) => k);
  if (kinds.length === 0) {
    return { rows: [], total: 0, offset, backend: "file", truncated: false, elapsedMs: 0, kinds };
  }
  if (types || channels || hasFlagFilter(flags)) {
    return fetchCrossKindPage(
      runId,
      kinds,
      offset,
      limit,
      signal,
      filter,
      types ?? [],
      started,
      flags,
      channels,
    );
  }
  if (filter) {
    // Path filter: one request with every category kind (repeatable kind=), first window only.
    const window = await artifactWindow(
      runId,
      { kind: kinds, offset: 0, limit, path_contains: filter, artifact_type: types },
      signal,
    );
    const rows: RawRow[] = [];
    for (const k of kinds) {
      for (const [i, row] of asRows(window[k]?.artifacts).entries()) rows.push(withLocator(row, k, i));
    }
    const flags = pageFlags(Object.values(window));
    return {
      rows,
      total: offset === 0 ? rows.length : null,
      offset,
      backend: "file",
      hasMore: false,
      truncated: flags.truncated || flags.hasMore,
      scanned: flags.scanned,
      elapsedMs: Math.round(now() - started),
      kinds,
    };
  }
  const { rows, total } = await pageAcrossKinds(runId, counts, offset, limit, signal);
  return {
    rows,
    total,
    offset,
    backend: "file",
    truncated: false,
    elapsedMs: Math.round(now() - started),
    kinds,
  };
}

/** Unified search (FTS when the run has a case DB, else a bounded scan). Not paged by the API. */
export async function fetchSearchRows(
  runId: string,
  query: Pick<CollectionQuery, "search" | "extension">,
  limit: number,
  signal?: AbortSignal,
): Promise<RawPage> {
  const spec = query.search;
  if (!spec || spec.keywords.length === 0) {
    return { rows: [], total: 0, offset: 0, backend: "none", truncated: false, elapsedMs: 0 };
  }
  const params = new URLSearchParams();
  for (const keyword of spec.keywords) params.append("keyword", keyword);
  params.set("limit", String(Math.min(limit, 1000)));
  params.set("search_mode", spec.mode);
  for (const source of spec.sources ?? []) params.append("source", source);
  for (const extension of query.extension ?? []) params.append("extension", extension);
  if (spec.hideKnownGood) params.set("hide_known_good", "true");
  const payload = await api<Record<string, unknown>>(`/api/runs/${enc(runId)}/search?${params}`, { signal });
  const rows = asRows(payload.matches);
  return {
    rows,
    total: rows.length,
    offset: 0,
    backend: typeof payload.backend === "string" ? payload.backend : "scan",
    truncated: payload.truncated === true,
    elapsedMs: asNumber(payload.elapsed_ms) ?? 0,
  };
}

/**
 * Review board = the run's case-DB review marks (GET /review-map, canonical store)
 * followed by any case.json bookmarks (fallback store when no case DB could be
 * created). Whole collection, client paged. Rows carry `_store`.
 */
/**
 * A case-DB mark that no longer says anything: a toggled-off status (`unreviewed`, or empty)
 * with no tags, note or report flag. The board (and its count) leaves it out.
 */
export function isClearedReviewMark(raw: RawRow): boolean {
  const status = typeof raw.status === "string" ? raw.status.trim() : "";
  if (status && status !== "unreviewed") return false;
  if (raw.include_in_report === true) return false;
  if (Array.isArray(raw.tags) && raw.tags.some((tag) => String(tag ?? "").trim())) return false;
  return !(typeof raw.note === "string" && raw.note.trim());
}

export async function fetchReviewRows(runId: string, signal?: AbortSignal): Promise<RawPage> {
  const started = now();
  const [map, casePayload] = await Promise.all([
    api<{ marks?: unknown; truncated?: unknown }>(`/api/runs/${enc(runId)}/review-map`, { signal }),
    api<{ exists?: boolean; case?: { bookmarks?: unknown } | null }>(`/api/runs/${enc(runId)}/case`, {
      signal,
    }).catch(() => ({ case: null })),
  ]);
  const rows = [
    ...asRows(map.marks)
      .filter((row) => !isClearedReviewMark(row))
      .map((row) => ({ ...row, _store: "case-db" })),
    ...asRows(casePayload.case?.bookmarks).map((row) => ({ ...row, _store: "bookmarks" })),
  ];
  return {
    rows,
    total: rows.length,
    offset: 0,
    backend: "case-db",
    truncated: map.truncated === true,
    elapsedMs: Math.round(now() - started),
  };
}

export async function fetchOutputRows(runId: string, signal?: AbortSignal): Promise<RawPage> {
  const started = now();
  const payload = await api<{ files?: unknown }>(`/api/runs/${enc(runId)}/output-files`, { signal });
  const rows = asRows(payload.files);
  return {
    rows,
    total: rows.length,
    offset: 0,
    backend: "file",
    truncated: false,
    elapsedMs: Math.round(now() - started),
  };
}

// ---- review / bookmark / extract actions ---------------------------------

export interface CaseDbHandle {
  database: string;
  case_id: string;
}

/** POST /api/runs/{id}/case-db/ensure — the run's canonical case DB (created/imported once). */
export function ensureCaseDb(runId: string): Promise<CaseDbHandle> {
  return api<CaseDbHandle>(`/api/runs/${enc(runId)}/case-db/ensure`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export interface ReviewMarkBody {
  status?: string;
  verification_status?: string;
  include_in_report?: boolean;
  /** Replaces the row's tags. */
  tags?: string[];
  /** Merged into the row's existing tags (server side). */
  add_tags?: string[];
  note?: string;
  /** Review author (AXIOM E3); overrides the "web-ui" default below. */
  reviewer?: string;
}

/** A case-db row, or a run-output locator the server resolves against `run_id`. */
export type ReviewBatchTarget =
  | { target_type: string; target_id: string }
  | { collection: string; kind?: string; locator: string };

export function postReviewBatch(
  handle: CaseDbHandle,
  targets: ReviewBatchTarget[],
  mark: ReviewMarkBody,
  runId?: string,
): Promise<{ updated_count?: number }> {
  return api("/api/case-db/review-batch", {
    method: "POST",
    body: JSON.stringify({
      database: handle.database,
      case_id: handle.case_id,
      ...(runId ? { run_id: runId } : {}),
      targets,
      reviewer: "web-ui",
      ...mark,
    }),
  });
}

export interface BookmarkBody {
  /** Output alias: files | docs | timeline | indicators | artifacts:<kind>. */
  source: string;
  /** JSON pointer inside that output, e.g. /candidates/894. */
  pointer: string;
  tags?: string[];
  note?: string;
  review_status?: string;
  include_in_report?: boolean;
}

export function postBookmark(runId: string, body: BookmarkBody): Promise<unknown> {
  return api(`/api/runs/${enc(runId)}/bookmarks`, { method: "POST", body: JSON.stringify(body) });
}
