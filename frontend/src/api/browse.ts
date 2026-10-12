import { api } from "./client";

export interface BrowseEntry {
  name: string;
  path: string;
  kind: "directory" | "file";
  size_bytes?: number | null;
  evidence_candidate?: boolean;
}

export interface BrowseListing {
  path: string;
  parent: string | null;
  home: string;
  separator: string;
  roots: Array<{ name?: string; path: string } | string>;
  entries: BrowseEntry[];
  entry_count: number;
  truncated: boolean;
  hidden_count: number;
  /** Scoped listing (`scope=`): true for the root list itself (`path` is ""). */
  at_roots?: boolean;
  /** Scoped listing: Korean name of the scope ("입력 허용 루트" …). */
  scope_label?: string;
}

/**
 * Analysis dialog picker scope: only the run's allowed input / output roots are listed
 * (`GET /api/browse?scope=analysis-input&run_id=`; no `path` = the roots themselves).
 */
export interface BrowseScope {
  name: "analysis-input" | "analysis-output";
  runId: string;
}

/** `GET /api/browse?path=` — server-side file picker (names only, never contents). */
export function browseDirectory(
  path?: string | null,
  showHidden = false,
  scope?: BrowseScope | null,
): Promise<BrowseListing> {
  const params = new URLSearchParams();
  if (path) params.set("path", path);
  if (showHidden) params.set("show_hidden", "true");
  if (scope) {
    params.set("scope", scope.name);
    params.set("run_id", scope.runId);
  }
  const query = params.toString();
  return api<BrowseListing>(`/api/browse${query ? `?${query}` : ""}`);
}
