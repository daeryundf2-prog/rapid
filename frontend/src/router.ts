/**
 * Hash router (plan U6): `#/case/{runId}/{collectionId}[/{sub}]?q=&row=&mode=`.
 *
 * The hash is the single source of truth for "where am I": the store's
 * `route` slice is always `parseHash(location.hash)`. Navigation writes the
 * hash (push = new history entry, replace = same entry) and the store follows,
 * so back/forward, refresh and copied links all restore the same screen.
 *
 * `{sub}` is the artifact kind for `artifacts` and the review status for
 * `review`; other collections ignore it. The `#token=` launch fragment is
 * not a route: it is captured by `captureLaunchToken()` and stripped while
 * any route that rides along in the same fragment is kept.
 */

import { captureFragmentToken } from "./api/client";
import type { CollectionId, ReviewStatus } from "./contracts/collection";
import { decodeRowRef, encodeRowRef, type RowRef } from "./contracts/rowRef";
import type { ViewerMode } from "./contracts/viewer";

export interface Route {
  runId: string | null;
  collection: CollectionId | null;
  /** Artifact kind (collection === "artifacts"). */
  kind?: string;
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
  /** Explorer view over the collection (X12, S9), URL `view=`; absent = "columns". */
  view?: ExplorerView;
  /** Artifact category node (X11, S7; collection === "artifacts", no kind), URL `category=`. */
  category?: string;
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

  const route: Route = {
    runId: segments[1],
    collection: isCollectionId(segments[2]) ? segments[2] : "intake",
  };
  const sub = segments[3];
  if (sub && route.collection === "artifacts") route.kind = sub;
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
    } else if (key === "category" && value && route.collection === "artifacts" && !route.kind) {
      route.category = safeDecode(value);
    } else if (key === "path" && value) route.path = safeDecode(value);
    else if (key === "status" && value) {
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
  let path = `#/case/${encodeURIComponent(route.runId)}/${collection}`;
  if (collection === "artifacts" && route.kind) path += `/${encodeURIComponent(route.kind)}`;
  if (collection === "review" && route.status) path += `/${route.status}`;
  const query: string[] = [];
  if (collection === "artifacts" && !route.kind && route.category) {
    query.push(`category=${encodeURIComponent(route.category)}`);
  }
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
  if (route.tz) query.push(`tz=${encodeURIComponent(route.tz)}`);
  if (route.view && route.view !== "columns") query.push(`view=${route.view}`);
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
    a.category !== b.category
  );
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
  const handler = () => listener(currentHashRoute());
  window.addEventListener("hashchange", handler);
  window.addEventListener("popstate", handler);
  return () => {
    window.removeEventListener("hashchange", handler);
    window.removeEventListener("popstate", handler);
  };
}
