// 탐색기 API (plan r4 §2.2 V2): file system tree, registry tree/values, media similar/groups.
//
//   GET /api/runs/{run}/fs-tree?path=&scope=&limit=&after=
//   GET /api/runs/{run}/registry-tree[?hive=&key=&limit=&after=]
//   GET /api/runs/{run}/registry-values?hive=&key=
//   GET /api/runs/{run}/media/similar?ref=&max_distance=&limit=
//   GET /api/runs/{run}/media/groups?by=camera|date[&key=]

import { api } from "./client";

const enc = encodeURIComponent;

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

// --- file system ------------------------------------------------------------------------

export type FsScope = "candidates" | "inventory";

export interface FsFolder {
  name: string;
  /** Relative to the volume root, `/` separators; `""` = root. */
  path: string;
  direct_file_count: number;
  direct_size: number;
  /** Recursive (the folder and every subfolder). */
  file_count: number;
  size: number;
  folder_count: number;
  has_children: boolean;
}

export interface FsSpecialNode {
  id: "orphan" | "unallocated" | "slack";
  label: string;
  count: number;
  /** Rows per list (files-sourced nodes only). */
  counts?: Record<FsScope, number>;
  source: "files" | "ntfs-meta" | "carve";
  files_query?: { special: string };
  analysis?: { analysis_id: string; kind: string };
  note?: string;
}

export interface FsTreePage {
  run_id: string;
  scope: FsScope;
  scope_counts: Record<FsScope, number>;
  volume: {
    id: string;
    label: string;
    root: string | null;
    filesystem: string | null;
    partition_start_sector: number | null;
    source_image: string | null;
  };
  node: FsFolder;
  breadcrumb: Array<{ name: string; path: string }>;
  children: FsFolder[];
  child_total: number;
  limit: number;
  next_after: string | null;
  special_nodes?: FsSpecialNode[];
  hidden_special_nodes?: Array<{ id: string; label: string; reason: string }>;
  index: {
    rows: number;
    indexed: number;
    outside_root: number;
    folders: number;
    truncated: boolean;
    reason?: string;
    outside_root_reason?: string;
  };
}

export function fetchFsTree(
  runId: string,
  options: { path?: string; scope?: FsScope; limit?: number; after?: string | null },
  signal?: AbortSignal,
): Promise<FsTreePage> {
  return api<FsTreePage>(
    `/api/runs/${enc(runId)}/fs-tree${query({
      path: options.path || undefined,
      scope: options.scope && options.scope !== "candidates" ? options.scope : undefined,
      limit: options.limit,
      after: options.after ?? undefined,
    })}`,
    { signal },
  );
}

// --- registry ----------------------------------------------------------------------------

export interface RegistryHive {
  id: string;
  name: string;
  path: string;
  mount: string;
  label: string;
  key_count: number;
  root_last_written_at: string | null;
}

export interface RegistryKey {
  name: string;
  key_path: string;
  last_written_at: string | null;
  value_count: number | null;
  subkey_count: number;
  child_count: number;
  has_children: boolean;
  record_index: number | null;
  synthetic: boolean;
  linked_row_count: number;
}

export interface RegistryIndexInfo {
  key_rows: number;
  keys: number;
  hives: number;
  truncated: boolean;
  reason?: string;
}

export interface RegistryHiveList {
  run_id: string;
  hives: RegistryHive[];
  reason?: string;
  index: RegistryIndexInfo | null;
}

export interface RegistryLevel {
  run_id: string;
  hive: RegistryHive;
  key: RegistryKey;
  breadcrumb: Array<{ name: string; key: string }>;
  children: RegistryKey[];
  child_total: number;
  limit: number;
  next_after: string | null;
  index: RegistryIndexInfo;
}

export interface RegistryValue {
  name: string;
  display_name: string;
  type: string | null;
  type_code: number | null;
  data_size: number | null;
  data_hex: string | null;
  data_truncated: boolean;
  decoded: string | number | string[] | null;
  decoded_kind: "text" | "number" | "list" | "binary" | "empty" | "too-large" | "unavailable";
  decoded_hex?: string;
  decoded_truncated?: boolean;
}

export interface RegistryLinkedRow {
  kind: string;
  record_index: number;
  artifact_type: string;
  label: string;
  locator: string;
}

export interface RegistryValues {
  run_id: string;
  hive: RegistryHive;
  key: RegistryKey;
  values: RegistryValue[];
  value_total: number;
  values_status: "parsed" | "names-only";
  reason?: string;
  citation: {
    text: string;
    hive_path: string;
    key_path: string;
    last_written_at: string | null;
    cell_offset: number | null;
    kind: string;
    record_index: number | null;
    locator: string | null;
  };
  artifact_rows: RegistryLinkedRow[];
  artifact_row_total: number;
  artifact_types: Record<string, number>;
}

export function fetchRegistryHives(runId: string, signal?: AbortSignal): Promise<RegistryHiveList> {
  return api<RegistryHiveList>(`/api/runs/${enc(runId)}/registry-tree`, { signal });
}

export function fetchRegistryLevel(
  runId: string,
  options: { hive: string; key?: string; limit?: number; after?: string | null },
  signal?: AbortSignal,
): Promise<RegistryLevel> {
  return api<RegistryLevel>(
    `/api/runs/${enc(runId)}/registry-tree${query({
      hive: options.hive,
      key: options.key || undefined,
      limit: options.limit,
      after: options.after ?? undefined,
    })}`,
    { signal },
  );
}

export function fetchRegistryValues(
  runId: string,
  hive: string,
  key: string,
  signal?: AbortSignal,
): Promise<RegistryValues> {
  return api<RegistryValues>(
    `/api/runs/${enc(runId)}/registry-values${query({ hive, key: key || undefined })}`,
    {
      signal,
    },
  );
}

// --- media -------------------------------------------------------------------------------

export interface SimilarMediaItem {
  path: string;
  name: string;
  kind: string;
  record_index: number;
  locator: string;
  distance: number;
  same_hash: boolean;
  sha256: string | null;
  camera: string | null;
  captured_at: string | null;
}

export interface SimilarMedia {
  run_id: string;
  ref: { path: string; record_index: number; perceptual_hash: string; sha256: string | null };
  max_distance: number;
  limit: number;
  items: SimilarMediaItem[];
  counts: {
    indexed: number;
    with_phash: number;
    same_hash: number;
    near: number;
    matched: number;
    returned: number;
  };
}

/** The 관련 미디어 pHash rule: distance ≤ 8 (plan r4 §2.2). */
export const RELATED_PHASH_DISTANCE = 8;
export const MAX_PHASH_DISTANCE = 16;

export function fetchSimilarMedia(
  runId: string,
  ref: string,
  options: { maxDistance?: number; limit?: number } = {},
  signal?: AbortSignal,
): Promise<SimilarMedia> {
  return api<SimilarMedia>(
    `/api/runs/${enc(runId)}/media/similar${query({
      ref,
      max_distance: options.maxDistance,
      limit: options.limit,
    })}`,
    { signal },
  );
}

export type MediaGroupBy = "camera" | "date";

export interface MediaGroups {
  run_id: string;
  by: MediaGroupBy;
  groups: Array<{ key: string; label: string; count: number; sample_paths: string[] }>;
  key?: string;
  paths?: string[];
  path_total?: number;
  paths_truncated?: boolean;
}

export function fetchMediaGroups(
  runId: string,
  by: MediaGroupBy,
  key?: string,
  signal?: AbortSignal,
): Promise<MediaGroups> {
  return api<MediaGroups>(`/api/runs/${enc(runId)}/media/groups${query({ by, key })}`, { signal });
}
