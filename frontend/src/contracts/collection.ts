/**
 * Collection contract (S0, console-redesign plan §5).
 *
 * A collection is one node of the navigation tree that renders in the single
 * DataGrid. Every collection is addressed by a stable id that also appears in
 * the URL (`#/case/{runId}/{collectionId}`), and is served by one API that
 * supports offset/limit paging so the grid never loads a whole output file.
 */

import type { RowRef } from "./rowRef";

export type CollectionId =
  | "intake"
  | "search"
  | "files"
  | "docs"
  | "artifacts"
  | "timeline"
  | "indicators"
  | "review"
  | "outputs";

/** Artifact kinds nest under "artifacts" (one child node per kind). */
export interface CollectionRef {
  id: CollectionId;
  /** Artifact kind (e.g. "eventlog") when id === "artifacts"; undefined = all kinds. */
  kind?: string;
  /** Review status filter when id === "review". */
  status?: ReviewStatus;
  /**
   * Artifact category (features/tree/categories.ts id) when id === "artifacts"
   * and no kind is set: the grid shows every kind of that category
   * (`kindsForCategory`). Route: `#/case/{run}/artifacts?category=<id>`.
   */
  category?: string;
}

/** Server sort key: `timestamp` or `details.<name>`; URL `sort=<key>:<order>`. */
export interface ServerSort {
  key: string;
  order: "asc" | "desc";
}

/** `sort` object of an artifacts response (plan artifact-columns §4.1). */
export interface ServerSortState extends ServerSort {
  status: "ready" | "building" | "unsupported";
  /** 0..1 while building. */
  progress: number;
  reason?: string;
}

export type ReviewStatus = "relevant" | "needs-review" | "excluded" | "include-in-report";

/** Server-side query the grid sends; the hook maps it to the collection's API. */
export interface CollectionQuery {
  ref: CollectionRef;
  offset: number;
  limit: number;
  /** Free text applied server-side where supported (path_contains / FTS), else client-side. */
  text?: string;
  extension?: string[];
  /** Server-side path substring (artifacts path_contains); wins over the single-token text. */
  pathContains?: string;
  /** Inclusive ISO range on the row timestamp (server-side only where an API supports it, else client). */
  timeRange?: { from?: string; to?: string };
  reviewStatus?: ReviewStatus[];
  tags?: string[];
  artifactTypes?: string[];
  /** Navigation category (tree) filter; interpreted by the collection. */
  category?: string;
  /**
   * Server-side sort (artifacts of exactly one kind; `GET /artifacts?sort=&order=`).
   * Other collections sort their loaded rows on the client and never send this.
   */
  sort?: ServerSort;
  /** Search-collection only. */
  search?: {
    keywords: string[];
    mode: "exact" | "fuzzy" | "regex";
    sources?: string[];
    hideKnownGood?: boolean;
  };
}

export interface CollectionPage<Row = GridRow> {
  rows: Row[];
  /** Total rows in the collection after server filters; null when unknown (scan backend). */
  total: number | null;
  offset: number;
  limit: number;
  /** "fts" | "scan" | "file" — surfaced in the grid footer. */
  backend: string;
  truncated: boolean;
  elapsedMs: number;
}

/**
 * Normalised row every collection must produce. Columns may add any extra
 * fields under `fields`, but these keys are what the viewer, the review
 * actions and the URL need.
 */
export interface GridRow {
  /** Stable and unique within a run: `${collection}[:${kind}]:${locator}` — see RowRef. */
  rowKey: string;
  ref: RowRef;
  /** Primary label (file name, event summary, keyword hit…). */
  title: string;
  /** Evidence path shown in the path column and sent to the viewer. */
  sourcePath: string | null;
  timestamp: string | null;
  artifactType: string | null;
  provider: string | null;
  sha256: string | null;
  reviewStatus: ReviewStatus | null;
  tags: string[];
  /** Collection-specific columns (already JSON-safe, hoisted profiles expanded by the API). */
  fields: Record<string, unknown>;
}
