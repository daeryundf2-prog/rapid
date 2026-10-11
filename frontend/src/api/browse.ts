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
}

/** `GET /api/browse?path=` — server-side file picker (names only, never contents). */
export function browseDirectory(path?: string | null, showHidden = false): Promise<BrowseListing> {
  const params = new URLSearchParams();
  if (path) params.set("path", path);
  if (showHidden) params.set("show_hidden", "true");
  const query = params.toString();
  return api<BrowseListing>(`/api/browse${query ? `?${query}` : ""}`);
}
