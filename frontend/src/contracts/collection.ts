/**
 * Collection contract (S0, console-redesign plan §5).
 *
 * A collection is one node of the navigation tree that renders in the single
 * DataGrid. Every collection is addressed by a stable id that also appears in
 * the URL (`#/case/{runId}/{collectionId}`), and is served by one API that
 * supports offset/limit paging so the grid never loads a whole output file.
 */

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
  sort?: { column: string; direction: "asc" | "desc" };
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
  /** Stable within a run: `${collection}:${locator}` — see RowRef. */
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
