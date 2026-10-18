/**
 * Hash router (plan U6, console-ia §3): `#/case/{runId}/{stage}/{view}[/{sub}]?q=&row=&mode=`.
 *
 * Stages (the rail, Alt+1..5 (Ctrl+1..5 is browser tab switching)): intake · process · explore · review · report. Inside the
 * app a route is still addressed by its collection (the view the grid / pane shows); the
 * stage is derived from it (`stageOf`). URL shapes:
 *   intake  `#/case/{run}/intake`
 *   process `#/case/{run}/process[/{analysis node}]`
 *   explore `#/case/{run}/explore/{files|docs|artifacts|timeline|indicators|search|analysis}[/{kind}]`
 *   review  `#/case/{run}/review/board[/{status}]`
 *   report  `#/case/{run}/report/outputs`
 * Legacy links `#/case/{run}/{collection}[/{sub}]` parse to the same route and are rewritten
 * to the stage form (`canonicalizeHash`, history replace).
 *
 * The hash is the single source of truth for "where am I": the store's
 * `route` slice is always `parseHash(location.hash)`. Navigation writes the
 * hash (push = new history entry, replace = same entry) and the store follows,
 * so back/forward, refresh and copied links all restore the same screen.
 *
 * `{sub}` is the artifact kind for `artifacts`, the analysis node kind for
 * `analysis` (with `id=<analysis_id>`) and the review status for `review`;
 * other collections ignore it. The `#token=` launch fragment is
 * not a route: it is captured by `captureLaunchToken()` and stripped while
 * any route that rides along in the same fragment is kept.
 */

import { captureFragmentToken } from "./api/client";
import {
  type CollectionId,
  type ColumnFilter,
  RECORD_FIELD_KEYS,
  type RecordFieldFilters,
  type RecordFieldKey,
  type ReviewStatus,
  type ServerSort,
} from "./contracts/collection";

/** Workflow stages of the rail (console-ia §3), in rail order. */
export type Stage = "intake" | "process" | "explore" | "review" | "report";
export const STAGES: readonly Stage[] = ["intake", "process", "explore", "review", "report"];

export function isStage(value: string | null | undefined): value is Stage {
  return !!value && (STAGES as readonly string[]).includes(value);
}

/** Views of the explore stage (the data collections the grid shows). */
export const EXPLORE_VIEWS: readonly CollectionId[] = [
  "files",
  "docs",
  "artifacts",
  "timeline",
  "indicators",
  "search",
  "analysis",
  "derived",
];

/** The stage a collection belongs to. */
export function stageOfCollection(collection: CollectionId | null | undefined): Stage {
  switch (collection) {
    case "process":
      return "process";
    case "review":
      return "review";
    case "outputs":
      return "report";
    case "intake":
    case null:
    case undefined:
      return "intake";
    default:
      return "explore";
  }
}

export function stageOf(route: Pick<Route, "collection">): Stage {
  return stageOfCollection(route.collection);
}

/**
 * Stages whose centre lists rows the viewer previews (visual-polish S9). 접수·처리·보고 are
 * two columns — left panel + page — and mount no viewer.
 */
export const VIEWER_STAGES: readonly Stage[] = ["explore", "review"];

export function stageHasViewer(stage: Stage): boolean {
  return VIEWER_STAGES.includes(stage);
}

/** Disabled reason of viewer commands on a stage without a viewer. */
export const NO_VIEWER_REASON = "이 단계에는 뷰어가 없습니다";

import { decodeRowRef, encodeRowRef, type RowRef } from "./contracts/rowRef";
import type { ViewerMode } from "./contracts/viewer";

export interface Route {
  runId: string | null;
  collection: CollectionId | null;
  /** Artifact kind (collection === "artifacts") or analysis node kind (collection === "analysis"). */
  kind?: string;
  /** Analysis job shown by the analysis node, URL `id=` (collection === "analysis"). */
  analysisId?: string;
  /** Review status filter (collection === "review"). */
  status?: ReviewStatus;
  /** Free-text query (search collection: FTS keywords; elsewhere: grid filter). */
  q?: string;
  /** Row shown in the viewer. */
  row?: RowRef;
  /** Viewer mode for `row`. */
  mode?: ViewerMode;
  /** Filter bar (X19): time range start/end (ISO or `YYYY-MM-DDTHH:mm`), URL `from`/`to`. */
  from?: string;
  to?: string;
  /** Display timezone: "utc" | "local" | IANA name (X4), URL `tz=`. */
  tz?: string;
  /** Review-status chips, URL `status=a,b`. */
  statuses?: ReviewStatus[];
  /** Artifact types, URL `types=`. */
  types?: string[];
  /** Tags, URL `tags=`. */
  tags?: string[];
  /** Extensions without dot, URL `ext=`. */
  ext?: string[];
  /** Path-contains text, URL `path=`. */
  path?: string;
  /** Only rows that carry a review note, URL `note=1` (검토 › 메모 있음). */
  notes?: boolean;
  /** Explorer view over the collection (X12, S9), URL `view=`; absent = "columns". */
  view?: ExplorerView;
  /** Artifact category node (X11, S7; artifacts without a kind) or files category (`GET /files?category=`), or docs `matched` (일치만, plain `GET /docs`), URL `category=`. */
  category?: string;
  /** Server sort of one artifact kind, URL `sort=details.run_count:desc` (artifacts with a kind only). */
  sort?: ServerSort;
  /** Promoted record-field columns of one artifact kind, URL `cols=details.a,details.b`. */
  cols?: string[];
  /** Column header filters, URL `cf=` (grammar: `parseColumnFilters`). */
  cf?: ColumnFilter[];
  /** 특이사항 rule ids, URL `flag=` (repeated; viewer-families U-F4). */
  flags?: string[];
  /** 특이사항 minimum grade, URL `flag_grade=A|B|C`. */
  flagGrade?: "A" | "B" | "C";
  /** Exact record-field filters, URL `browser=` / `service=` (repeated; artifacts server-side). */
  fields?: RecordFieldFilters;
}

/** Collections whose `{sub}` is a kind with server sort / promoted columns (`sort=`, `cols=`). */
function hasKindSort(route: Pick<Route, "collection" | "kind">): boolean {
  return (route.collection === "artifacts" || route.collection === "analysis") && Boolean(route.kind);
}

// --- column header filters (`cf=`) ----------------------------------------------
//
// Grammar (plan analysis-workbench-p1 §4, 구현 메모):
//   cf      = entry *( "," entry )
//   entry   = enc(col) op enc(value)
//   op      = ":" | ">" | "<"          ; ":" contains (text) or "from..to" (time), ">" min, "<" max
// `enc` is encodeURIComponent, so a column id or value never carries a raw "," ":" "<" ">";
// the FIRST operator after the column id splits the entry (browsers may percent-encode a
// raw "<" / ">" in the fragment as %3C / %3E, which is read back as the operator).
// Examples: `cf=path:foo,size>1000,timestamp:2025-01-01..2025-02-01`.

const CF_OPERATOR = /:|>|<|%3[ceCE]/;

/** Parse a `cf=` value (still URL-encoded) into column filters; malformed entries are dropped. */
export function parseColumnFilters(value: string): ColumnFilter[] {
  const out: ColumnFilter[] = [];
  for (const entry of value.split(",")) {
    const match = CF_OPERATOR.exec(entry);
    if (!match || match.index === 0) continue;
    const token = match[0].toLowerCase();
    const op: ColumnFilter["op"] = token === ":" ? ":" : token === ">" || token === "%3e" ? ">" : "<";
    const col = safeDecode(entry.slice(0, match.index)).trim();
    const raw = safeDecode(entry.slice(match.index + match[0].length));
    if (!col || /[<>%,]/.test(col) || raw.trim() === "") continue;
    out.push({ col, op, value: raw.trim() });
  }
  return out;
}

/** Serialise column filters for `cf=` (inverse of `parseColumnFilters`). */
export function serializeColumnFilters(filters: readonly ColumnFilter[]): string {
  return filters
    .filter((f) => f.col && f.value.trim() !== "")
    .map((f) => `${encodeURIComponent(f.col)}${f.op}${encodeURIComponent(f.value.trim())}`)
    .join(",");
}

/** `timestamp` or `details.<scalar key>` (plan artifact-columns §4.1). */
export function isServerSortKey(key: string): boolean {
  return key === "timestamp" || key === "flags" || /^details\.[^\s,:]+$/.test(key);
}

/** `key:order` -> ServerSort; order defaults to asc. Null when the key is not a server sort key. */
export function parseSortParam(value: string): ServerSort | null {
  const colon = value.lastIndexOf(":");
  const key = colon > 0 ? value.slice(0, colon) : value;
  const rawOrder = colon > 0 ? value.slice(colon + 1).toLowerCase() : "asc";
  if (!isServerSortKey(key) || (rawOrder !== "asc" && rawOrder !== "desc")) return null;
  return { key, order: rawOrder };
}

/** Explorer views (S9 ViewSwitch). "columns" is the default DataGrid and is never written to the URL. */
export type ExplorerView = "columns" | "thumbnails" | "chat" | "histogram";
export const EXPLORER_VIEWS: readonly ExplorerView[] = ["columns", "thumbnails", "chat", "histogram"];

function listParam(value: string): string[] {
  return value
    .split(",")
    .map((part) => safeDecode(part).trim())
    .filter(Boolean);
}

export const COLLECTION_IDS: readonly CollectionId[] = [
  "intake",
  "search",
  "files",
  "docs",
  "artifacts",
  "timeline",
  "indicators",
  "review",
  "outputs",
  "analysis",
  "process",
  "derived",
];

const REVIEW_STATUSES: readonly ReviewStatus[] = [
  "relevant",
  "needs-review",
  "excluded",
  "include-in-report",
];
const VIEWER_MODES: readonly ViewerMode[] = [
  "source",
  "hex",
  "sqlite",
  "image",
  "document",
  "email",
  "media",
  "meta",
];

export const EMPTY_ROUTE: Route = Object.freeze({ runId: null, collection: null }) as Route;

export function isCollectionId(value: string | null | undefined): value is CollectionId {
  return !!value && (COLLECTION_IDS as readonly string[]).includes(value);
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Parse a location hash (with or without the leading `#`). Unknown shapes → EMPTY_ROUTE. */
export function parseHash(hash: string): Route {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  if (!raw.startsWith("/")) return { ...EMPTY_ROUTE };
  const queryIndex = raw.indexOf("?");
  const pathPart = queryIndex >= 0 ? raw.slice(0, queryIndex) : raw;
  const queryPart = queryIndex >= 0 ? raw.slice(queryIndex + 1) : "";
  const segments = pathPart.split("/").filter(Boolean).map(safeDecode);
  if (segments[0] !== "case" || !segments[1]) return { ...EMPTY_ROUTE };

  const route: Route = { runId: segments[1], collection: "intake" };
  // Stage form `/{stage}/{view}/{sub}`; anything else is a legacy `/{collection}/{sub}` link.
  let view: string | undefined;
  let sub: string | undefined;
  const head = segments[2];
  if (isStage(head)) {
    if (head === "process") {
      route.collection = "process";
      if (segments[3]) route.kind = segments[3];
    } else if (head === "review") {
      route.collection = "review";
      sub = segments[3] === "board" ? segments[4] : segments[3];
    } else if (head === "report") {
      route.collection = "outputs";
    } else if (head === "explore") {
      view = segments[3];
      route.collection =
        view && (EXPLORE_VIEWS as readonly string[]).includes(view) ? (view as CollectionId) : "files";
      sub = segments[4];
    }
  } else {
    route.collection = isCollectionId(head) ? head : "intake";
    sub = segments[3];
  }
  if (sub && (route.collection === "artifacts" || route.collection === "analysis")) route.kind = sub;
  // 통합 보기: `{sub}` is the table (people, devices, paths, attachments, credentials, urls).
  if (sub && route.collection === "derived") route.kind = sub;
  if (sub && route.collection === "review" && (REVIEW_STATUSES as readonly string[]).includes(sub)) {
    route.status = sub as ReviewStatus;
  }

  for (const pair of queryPart.split("&")) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const key = eq >= 0 ? pair.slice(0, eq) : pair;
    const value = eq >= 0 ? pair.slice(eq + 1) : "";
    if (key === "q" && value) route.q = safeDecode(value);
    else if (key === "row" && value) {
      const ref = decodeRowRef(value);
      if (ref) route.row = ref;
    } else if (key === "mode" && (VIEWER_MODES as readonly string[]).includes(value)) {
      route.mode = value as ViewerMode;
    } else if (key === "from" && value) route.from = safeDecode(value);
    else if (key === "to" && value) route.to = safeDecode(value);
    else if (key === "tz" && value) route.tz = safeDecode(value);
    else if (key === "view" && value !== "columns" && (EXPLORER_VIEWS as readonly string[]).includes(value)) {
      route.view = value as ExplorerView;
    } else if (
      key === "category" &&
      value &&
      ((route.collection === "artifacts" && !route.kind) ||
        route.collection === "files" ||
        route.collection === "docs")
    ) {
      route.category = safeDecode(value);
    } else if (key === "path" && value) route.path = safeDecode(value);
    else if (key === "sort" && value && hasKindSort(route)) {
      const sort = parseSortParam(safeDecode(value));
      if (sort) route.sort = sort;
    } else if (key === "id" && value && route.collection === "analysis") {
      route.analysisId = safeDecode(value);
    } else if (key === "cf" && value) {
      const list = parseColumnFilters(value);
      if (list.length) route.cf = list;
    } else if (key === "cols" && value && hasKindSort(route)) {
      const list = listParam(value).filter((col) => col.startsWith("details.") && isServerSortKey(col));
      if (list.length) route.cols = [...new Set(list)];
    } else if (key === "status" && value) {
      const list = listParam(value).filter((v): v is ReviewStatus =>
        (REVIEW_STATUSES as readonly string[]).includes(v),
      );
      if (list.length) route.statuses = list;
    } else if (key === "types" && value) {
      const list = listParam(value);
      if (list.length) route.types = list;
    } else if (key === "tags" && value) {
      const list = listParam(value);
      if (list.length) route.tags = list;
    } else if (key === "flag" && value) {
      const id = safeDecode(value).trim();
      if (id && !(route.flags ?? []).includes(id)) route.flags = [...(route.flags ?? []), id];
    } else if (key === "flag_grade" && (value === "A" || value === "B" || value === "C")) {
      route.flagGrade = value;
    } else if ((RECORD_FIELD_KEYS as readonly string[]).includes(key) && value) {
      const field = key as RecordFieldKey;
      const item = safeDecode(value).trim();
      const list = route.fields?.[field] ?? [];
      if (item && !list.includes(item)) route.fields = { ...route.fields, [field]: [...list, item] };
    } else if (key === "note" && value === "1") {
      route.notes = true;
    } else if (key === "ext" && value) {
      const list = listParam(value);
      if (list.length) route.ext = list;
    }
  }
  return route;
}

/** Serialise a route to a hash string (`#/…`). Inverse of `parseHash` for valid routes. */
export function serializeRoute(route: Route): string {
  if (!route.runId) return "#/";
  const collection = route.collection ?? "intake";
  const base = `#/case/${encodeURIComponent(route.runId)}`;
  let path: string;
  switch (stageOfCollection(collection)) {
    case "intake":
      path = `${base}/intake`;
      break;
    case "process":
      path = `${base}/process${route.kind ? `/${encodeURIComponent(route.kind)}` : ""}`;
      break;
    case "review":
      path = `${base}/review/board${route.status ? `/${route.status}` : ""}`;
      break;
    case "report":
      path = `${base}/report/outputs`;
      break;
    default:
      path = `${base}/explore/${collection}`;
      if ((collection === "artifacts" || collection === "analysis") && route.kind) {
        path += `/${encodeURIComponent(route.kind)}`;
      }
      if (collection === "derived" && route.kind) path += `/${encodeURIComponent(route.kind)}`;
  }
  const query: string[] = [];
  if (
    ((collection === "artifacts" && !route.kind) || collection === "files" || collection === "docs") &&
    route.category
  ) {
    query.push(`category=${encodeURIComponent(route.category)}`);
  }
  if (collection === "analysis" && route.analysisId) query.push(`id=${encodeURIComponent(route.analysisId)}`);
  if (route.q) query.push(`q=${encodeURIComponent(route.q)}`);
  if (route.row) query.push(`row=${encodeRowRef(route.row)}`);
  if (route.row && route.mode) query.push(`mode=${route.mode}`);
  if (route.from) query.push(`from=${encodeURIComponent(route.from)}`);
  if (route.to) query.push(`to=${encodeURIComponent(route.to)}`);
  if (route.statuses?.length) query.push(`status=${route.statuses.join(",")}`);
  if (route.types?.length) query.push(`types=${route.types.map(encodeURIComponent).join(",")}`);
  if (route.tags?.length) query.push(`tags=${route.tags.map(encodeURIComponent).join(",")}`);
  if (route.ext?.length) query.push(`ext=${route.ext.map(encodeURIComponent).join(",")}`);
  if (route.path) query.push(`path=${encodeURIComponent(route.path)}`);
  if (route.notes) query.push("note=1");
  if (route.flagGrade) query.push(`flag_grade=${route.flagGrade}`);
  for (const id of route.flags ?? []) query.push(`flag=${encodeURIComponent(id)}`);
  for (const field of RECORD_FIELD_KEYS) {
    for (const item of route.fields?.[field] ?? []) query.push(`${field}=${encodeURIComponent(item)}`);
  }
  if (route.tz) query.push(`tz=${encodeURIComponent(route.tz)}`);
  if (route.view && route.view !== "columns") query.push(`view=${route.view}`);
  if (route.cf?.length) {
    const cf = serializeColumnFilters(route.cf);
    if (cf) query.push(`cf=${cf}`);
  }
  if (hasKindSort({ collection, kind: route.kind })) {
    if (route.sort) query.push(`sort=${encodeURIComponent(route.sort.key)}:${route.sort.order}`);
    if (route.cols?.length) query.push(`cols=${route.cols.map(encodeURIComponent).join(",")}`);
  }
  return query.length ? `${path}?${query.join("&")}` : path;
}

export function routesEqual(a: Route, b: Route): boolean {
  return serializeRoute(a) === serializeRoute(b);
}

/** True when the two routes show a different grid (run, collection or sub-node). */
export function collectionChanged(a: Route, b: Route): boolean {
  return (
    a.runId !== b.runId ||
    a.collection !== b.collection ||
    a.kind !== b.kind ||
    a.status !== b.status ||
    a.category !== b.category ||
    a.analysisId !== b.analysisId
  );
}

/** True for a case link in the pre-stage form (`#/case/{run}/{collection}…`), which is rewritten. */
export function isLegacyCaseHash(hash: string): boolean {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  const path = raw.split("?")[0] ?? "";
  const segments = path.split("/").filter(Boolean);
  return segments[0] === "case" && Boolean(segments[1]) && !isStage(segments[2]);
}

/**
 * Redirect a legacy case link to its stage form (history replace, no new entry). Returns the
 * route when the address bar was rewritten. Never touches a fragment still carrying `token=`.
 */
export function canonicalizeHash(): Route | null {
  if (typeof window === "undefined") return null;
  const hash = window.location.hash;
  if (!isLegacyCaseHash(hash) || /[#&?]token=/.test(hash)) return null;
  const route = parseHash(hash);
  window.history.replaceState(
    null,
    "",
    window.location.pathname + window.location.search + serializeRoute(route),
  );
  return route;
}

/** Remove `token=` from a fragment, keeping any route that shares it. */
export function stripTokenFromHash(hash: string): string {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  if (!raw.startsWith("/")) return "";
  const queryIndex = raw.indexOf("?");
  if (queryIndex < 0) return `#${raw}`;
  const kept = raw
    .slice(queryIndex + 1)
    .split("&")
    .filter((pair) => pair && !pair.startsWith("token="));
  const path = raw.slice(0, queryIndex);
  return kept.length ? `#${path}?${kept.join("&")}` : `#${path}`;
}

/**
 * Move a `#token=` launch fragment into session storage (client.ts) and strip
 * only the token from the address bar. Returns true when a token was found.
 */
export function captureLaunchToken(): boolean {
  // client.ts matches `[#&]token=`; a routed fragment carries it after `?`.
  const hash = window.location.hash.replace("?token=", "&token=");
  return captureFragmentToken(hash, undefined, () => {
    const next = stripTokenFromHash(window.location.hash);
    window.history.replaceState(null, "", window.location.pathname + window.location.search + next);
  });
}

export function currentHashRoute(): Route {
  return typeof window === "undefined" ? { ...EMPTY_ROUTE } : parseHash(window.location.hash);
}

/** Write a route to the address bar. Does not notify listeners (the store does that). */
export function writeHash(route: Route, replace: boolean): void {
  const next = serializeRoute(route);
  if (window.location.hash === next) return;
  const url = window.location.pathname + window.location.search + next;
  if (replace) window.history.replaceState(null, "", url);
  else window.history.pushState(null, "", url);
}

/** Subscribe to back/forward and manual hash edits. */
export function onHashChange(listener: (route: Route) => void): () => void {
  const handler = () => {
    canonicalizeHash();
    listener(currentHashRoute());
  };
  window.addEventListener("hashchange", handler);
  window.addEventListener("popstate", handler);
  return () => {
    window.removeEventListener("hashchange", handler);
    window.removeEventListener("popstate", handler);
  };
}
