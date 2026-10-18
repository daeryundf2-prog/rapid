import { api } from "./client";

export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface RunRequest {
  root?: string;
  mode?: string;
  output_dir?: string;
  input_kind?: string;
}

export interface RunListItem {
  run_id: string;
  status: RunStatus | string;
  created_at?: string;
  updated_at?: string;
  request?: RunRequest;
  origin?: string;
}

export interface RunJob extends RunListItem {
  summary?: RunSummary;
  steps?: Array<Record<string, unknown>>;
  error?: string;
}

export interface CanonicalCounts {
  validation_issues: number;
  validation_issue_breakdown?: {
    step_warnings: number;
    parser_errors: number;
  };
  outputs: number;
  artifacts: number;
  docs: number;
  /** Every document candidate (`docs` = keyword matches); servers before parser-quality r1 omit it. */
  document_candidates?: number;
  files: number;
  timeline_events: number;
  review_items: number;
  indicators: number;
}

export interface RunSummary {
  mode?: string;
  root?: string;
  output_dir?: string;
  summary?: {
    counts?: CanonicalCounts;
    [key: string]: unknown;
  };
  processing?: {
    warning_count?: number;
    [key: string]: unknown;
  };
  outputs?: Record<string, string>;
  steps?: Array<Record<string, unknown>>;
  /** Every step warning (caps, silent-failure verdicts, skipped providers), parser-quality r1. */
  warnings?: RunWarning[];
  /** Report-facing limits of the run (core/run/summary.py build_run_disclosures). */
  disclosures?: RunDisclosures;
}

export interface RunWarning {
  step?: string;
  level?: string;
  message?: string;
  [key: string]: unknown;
}

export interface RunDisclosures {
  time_origin?: string | null;
  acquisition_copy_note?: string;
  timezone?: {
    evidence_timezone?: { name?: string; label?: string; utc_offset?: string; bias_minutes?: number } | null;
    [key: string]: unknown;
  };
  registry_context?: Record<string, unknown>;
  missing_tools?: Record<string, { available?: boolean; note?: string }>;
  caps?: Record<string, string[]>;
  timeline_excluded?: { out_of_range?: number; duplicates?: number; copy_time_candidates?: number };
  documents?: {
    candidate_count?: number;
    match_count?: number;
    indexed_with_text_count?: number | null;
    encrypted_count?: number | null;
    zero_text_count?: number | null;
    text_status_counts?: Record<string, number>;
    /** Text-extraction size caps (core/docs.py build_docs_size_cap_disclosure, parser-quality r2). */
    size_caps?: DocsSizeCaps | null;
  };
  indicators?: {
    display_label?: string | null;
    rule_count?: number;
    total_before_cap?: number | null;
    truncated?: boolean | null;
    rule_status_message?: string | null;
    /** Indicator cap disclosure (core/indicators.py indicator_cap_policy, parser-quality r2). */
    cap_policy?: IndicatorCapPolicy | null;
  };
  files?: {
    excluded_file_count?: number | null;
    exclusion_reason_counts?: Record<string, number>;
    excluded_category_counts?: Record<string, number>;
  };
  collection_notes?: Record<string, string[]>;
  /** Run-level row truncation (core/run/summary.py `summarize_input_row_truncation`). */
  input_row_truncation?: InputRowTruncation | null;
  [key: string]: unknown;
}

/** `cap_policy` of the indicators summary: "uncapped" (상한 없음) or "capped" at `max_indicators`. */
export interface IndicatorCapPolicy {
  mode?: "uncapped" | "capped" | string;
  max_indicators?: number | null;
  kept?: number;
  total_before_cap?: number;
  note?: string;
}

/** docs summary `size_caps`: the byte caps of text extraction and the documents they stopped. */
export interface DocsSizeCaps {
  max_input_bytes?: number;
  max_archive_member_bytes?: number;
  max_archive_total_bytes?: number;
  max_pdf_stream_decompressed_bytes?: number;
  too_large_count?: number;
  binary_rejected_count?: number;
  truncated?: boolean;
  note?: string;
}

/** `disclosures.input_row_truncation`: run totals plus the per-step (`artifacts-<kind>`) breakdown. */
export interface InputRowTruncation {
  payload_truncated_rows?: number;
  preview_truncated_rows?: number;
  level?: "none" | "notice" | "warning" | string;
  by_step?: Record<string, RowTruncation>;
}

/**
 * Row-level truncation of one artifact kind (core/timeline.py `input_row_truncation`, mirrored on
 * the step as `row_truncation`): payload cuts (`rows_with_truncation`, `count_fields`) are warnings;
 * display-preview cuts (`preview_only_rows`) keep the record value and are notices.
 */
export interface RowTruncation {
  rows_with_truncation?: number;
  flag_counts?: Record<string, number>;
  count_fields?: Record<string, number>;
  preview_only_rows?: number;
  preview_flag_counts?: Record<string, number>;
  preview_count_fields?: Record<string, number>;
}

export async function listRuns(): Promise<RunListItem[]> {
  const payload = await api<{ runs: RunListItem[] }>("/api/runs");
  return payload.runs;
}

export function getRun(runId: string): Promise<RunJob> {
  return api<RunJob>(`/api/runs/${encodeURIComponent(runId)}`);
}

export function getRunSummary(runId: string): Promise<RunSummary> {
  return api<RunSummary>(`/api/runs/${encodeURIComponent(runId)}/summary`);
}

export interface TreeNode {
  id: string;
  label: string;
  count: number;
  collection?: string;
  kind?: string;
  artifact_type?: string;
  category?: string;
  /** Analysis nodes (`analysis:<kind>`): newest job state, null = never ran (plan analysis-workbench-p1 §3.3). */
  state?: { status?: string; finished_at?: string | null } | null;
  /**
   * Analysis nodes: newest completed job; R3 §3.3 sub-view counts ride along (`source_counts` of
   * ntfs-meta, `source_in_use_counts` (`timestamp-mismatch:in-use` / `:deleted`), `kind_counts` of carve).
   */
  latest_completed?: {
    analysis_id?: string;
    row_count?: number | null;
    source_counts?: Record<string, number>;
    source_in_use_counts?: Record<string, number>;
    kind_counts?: Record<string, number>;
  } | null;
  /**
   * Kind nodes: records per artifact_type. On the primary node (`artifacts:<kind>`) the whole
   * kind; on a routed node (`artifacts:<kind>@<domain>`) only the types placed in that domain.
   */
  artifact_type_counts?: Record<string, number>;
  /** Kind nodes (api/app/tree.py): the server domain id of the node's group. */
  domain?: string;
  /** Kind nodes: records per artifact_type placed in this node's domain. */
  domain_artifact_type_counts?: Record<string, number>;
  /** Kind nodes: the provider's `collection_status` when not "completed" (skipped / failed-isolated / partial). */
  collection_status?: string;
  /** Kind nodes: the provider's collection notes (why rows are missing or capped). */
  collection_notes?: string[];
  /**
   * Kind nodes of `browser` / `windows-messenger` (r2 console fix M2): rows per value of a record
   * field and artifact type, `{browser: {"ie-edge-legacy": {"browser-history": 3}}}` — the counts
   * of the `browser=` / `service=` filtered nodes.
   */
  field_type_counts?: Record<string, Record<string, Record<string, number>>>;
  /**
   * Kind nodes of `email` / `kakaotalk-windows` (M4): inventory rows by status with the Korean
   * reason (PST tools off / missing, KakaoTalk key material missing) — why a typed node is empty.
   */
  inventory_notes?: InventoryNote[];
  /** The facet scan stopped at its row cap: field counts / notes are partial. */
  facets_truncated?: boolean;
  /** Kind nodes: skipped-row reasons (`skip_reasons`, summary of artifacts.py) — not exposed by tree.py yet. */
  skip_reasons?: Record<string, number>;
  skip_reason?: string;
  /** Type nodes: rows that are string pivots, not evidence (`*-string-candidate`). */
  non_evidence?: boolean;
  /** `docs` node: every document candidate (count = keyword matches). */
  candidate_count?: number;
  match_count?: number;
  /** `indicators` node: detection rules applied (0 = the label is "지표 후보"). */
  rule_count?: number;
  /**
   * `files` node (parser-quality r2): scanned files outside the selected categories, kept as
   * lightweight inventory rows (`files.json` `inventory`, listed by `GET /files?scope=inventory`).
   */
  inventory_count?: number;
  /** `files:<category>` nodes: the category exists only in the inventory (e.g. "other"). */
  inventory_only?: boolean;
  /** `files:<category>` nodes: "inventory" when counted from the inventory rows. */
  source?: string;
  /** `artifacts:eventlog`: recovered records older than the first live record id (not sent by tree.py yet). */
  stale_below_first_record_count?: number;
  /** Kind nodes: flagged rows per highest grade (viewer-families U-F4, `triage-flags` summary). */
  flag_counts?: Partial<Record<"A" | "B" | "C", number>>;
  /** `artifacts:eventlog` (plan r3-os-depth §3.2 O2): rows per exact `details.channel` ("" = none). */
  channel_counts?: Record<string, number>;
  /** `artifacts:eventlog`: channel groups (core/eventlog_channels.py), Korean-sorted. */
  channel_groups?: ChannelGroupNode[];
  children?: TreeNode[];
}

/** One event-log channel group of `/tree` (`artifacts:eventlog` `channel_groups`). */
export interface ChannelGroupNode {
  id: string;
  label: string;
  /** Rows of the group; null when unknown (서비스(SCM) on an older output). */
  count: number | null;
  /** Exact channel names of the run in this group (the server `channel=` values). */
  channels: string[];
  /** False for 서비스(SCM): a view inside 시스템, not part of the channel partition. */
  partition: boolean;
  provider?: string;
}

/**
 * `/tree` `flags` section (viewer-families U-F4): artifact rows per highest grade, rows per rule,
 * and policy-dependent sources with their record counts ("부재 ≠ 미발생" when 0).
 */
export interface TreeFlagsSection {
  total?: number;
  by_grade?: Partial<Record<"A" | "B" | "C", number>>;
  by_rule?: Record<string, number> | Array<{ id: string; count: number; grade?: string; label?: string }>;
  policy?: Array<{ id: string; label?: string; count: number; note?: string }>;
  /** Rule-set versions the summary was computed with. */
  versions?: Record<string, string | number>;
}

export interface RunTree {
  run_id: string;
  root: { label?: string; mode?: string; status?: string };
  nodes: TreeNode[];
  /** Absent: the run has no triage-flags analysis yet. */
  flags?: TreeFlagsSection;
}

export function getRunTree(runId: string): Promise<RunTree> {
  return api<RunTree>(`/api/runs/${encodeURIComponent(runId)}/tree`);
}

export type ItemRow = Record<string, unknown>;

interface PaginatedRows {
  key: string;
  rows: ItemRow[];
  total: number;
}

async function paginated(runId: string, name: string, key: string, limit: number): Promise<PaginatedRows> {
  const payload = await api<Record<string, unknown>>(
    `/api/runs/${encodeURIComponent(runId)}/${name}?limit=${limit}`,
  );
  const rows = Array.isArray(payload[key]) ? (payload[key] as ItemRow[]) : [];
  const total = typeof payload.total === "number" ? payload.total : rows.length;
  return { key, rows, total };
}

export function getRunFiles(runId: string, limit = 500): Promise<PaginatedRows> {
  return paginated(runId, "files", "candidates", limit);
}

export function getRunDocs(runId: string, limit = 500): Promise<PaginatedRows> {
  return paginated(runId, "docs", "results", limit);
}

export function getRunTimeline(runId: string, limit = 500): Promise<PaginatedRows> {
  return paginated(runId, "timeline", "events", limit);
}

export function getRunIndicators(runId: string, limit = 500): Promise<PaginatedRows> {
  return paginated(runId, "indicators", "indicators", limit);
}

export async function getRunIssues(runId: string): Promise<PaginatedRows> {
  const payload = await api<{ issues: ItemRow[]; count: number }>(
    `/api/runs/${encodeURIComponent(runId)}/issues`,
  );
  return { key: "issues", rows: payload.issues ?? [], total: payload.count ?? 0 };
}

export interface ArtifactFamilies {
  [kind: string]: { artifacts?: ItemRow[]; total?: number };
}

export async function getRunArtifacts(runId: string, limit = 1000): Promise<ArtifactFamilies> {
  const payload = await api<{ artifacts: ArtifactFamilies }>(
    `/api/runs/${encodeURIComponent(runId)}/artifacts?limit=${limit}`,
  );
  return payload.artifacts ?? {};
}

/** Body of `POST /api/runs` — mirrors `RunCreateRequest` in rapidtriage/api/app/models.py. */
export interface RunCreateBody {
  root: string;
  mode: string;
  output_dir?: string | null;
  input_kind?: string | null;
  rules?: string | null;
  dry_run?: boolean;
  read_only?: boolean;
  max_extract_size_bytes?: number;
  max_file_count?: number;
  memory_cap_bytes?: number;
  e01_partition_start_sector?: number | null;
  overwrite?: boolean;
  resume?: boolean;
  extract?: boolean;
  known_good_hash_feeds?: string[];
  hide_known_good?: boolean;
  known_good_max_hash_bytes?: number;
  wait?: boolean;
}

export function createRun(body: RunCreateBody): Promise<RunJob> {
  return api<RunJob>("/api/runs", { method: "POST", body: JSON.stringify(body) });
}

/** `POST /api/runs/import` — `RunImportRequest`. */
export function importRun(outputDir: string): Promise<RunJob> {
  return api<RunJob>("/api/runs/import", { method: "POST", body: JSON.stringify({ output_dir: outputDir }) });
}

export async function deleteRun(runId: string): Promise<void> {
  await api<unknown>(`/api/runs/${encodeURIComponent(runId)}`, { method: "DELETE" });
}

/** `POST /api/sample-case/run` — `SampleCaseRunRequest`. */
export interface SampleCaseBody {
  output_dir?: string | null;
  mode?: string;
  overwrite?: boolean;
  read_only?: boolean;
}

export function runSampleCase(body: SampleCaseBody = {}): Promise<{ command: string; run: RunJob }> {
  return api("/api/sample-case/run", { method: "POST", body: JSON.stringify(body) });
}

export interface DoctorCheck {
  name: string;
  category: string;
  status: "ok" | "warn" | "error" | string;
  summary: string;
  details?: Record<string, unknown>;
  remediation?: string;
}

export interface DoctorReport {
  command: string;
  status: string;
  summary: { ok: number; warn: number; error: number; check_count: number };
  checks: DoctorCheck[];
}

export function getDoctor(): Promise<DoctorReport> {
  return api<DoctorReport>("/api/doctor");
}

export function getCollectProfiles(): Promise<{ profiles: string[] }> {
  return api<{ profiles: string[] }>("/api/collect/profiles");
}

/** `POST /api/collect/plan` — `CollectPlanRequest` (preview only; not part of the run request). */
export function planCollect(body: {
  root: string;
  profile: string;
  input_kind?: string | null;
}): Promise<Record<string, unknown>> {
  return api("/api/collect/plan", { method: "POST", body: JSON.stringify(body) });
}

/**
 * Query for `GET /api/runs/{id}/artifacts`.
 * - `kind` (repeatable): page only those kinds.
 * - `path_contains`: NFC case-insensitive substring on `path`, streamed; offset counts matches.
 *   Per-kind `pagination` then has `filtered`, `scanned`, `truncated`, and `total: null`
 *   unless the whole kind was scanned.
 * - `sort` (`timestamp` | `details.<key>`) + `order` (asc|desc): server sort of exactly one kind.
 *   The kind object then carries `sort: {key, order, status, progress, reason?}`; while
 *   `status === "building"` its `artifacts` is empty and the client polls (plan artifact-columns §4.1).
 * - Every row carries `record_index` (0-based JSONL index), sorted or not.
 */
/** One status of a kind's inventory rows (`/tree` `inventory_notes`). */
export interface InventoryNote {
  artifact_type: string;
  status: string;
  status_label?: string;
  count: number;
  reason?: string;
}

export interface ArtifactsQuery {
  offset?: number;
  limit?: number;
  kind?: string[];
  path_contains?: string;
  sort?: string;
  order?: "asc" | "desc";
  /** With `sort`: report the sorted position of this record_index as `sort.position`. */
  locate?: number;
  /** Server-side artifact_type filter (repeated `artifact_type=`; plan analysis-workbench-p1 §3.3). */
  artifact_type?: string[];
  /** 특이사항 filters (viewer-families §3.1): repeated `flag=` (any of), `flag_grade=` (at least). */
  flag?: string[];
  flag_grade?: string;
  /** Exact record-field filters (repeated `browser=` / `service=`; r2 console fix M2). */
  browser?: string[];
  service?: string[];
  /** Event-log channels (repeated `channel=`, exact `details.channel`; plan r3-os-depth §3.2 O2). */
  channel?: string[];
  /** Event-log channel groups (repeated `channel_group=`: security … other, none, services). */
  channel_group?: string[];
  /** Row conditions (r4 §2.3): `from`, `to`, `weekday`, `hours`, `offhours`, `tz`, `partial`, `content`, `geo`. */
  conditions?: Record<string, string | string[]>;
}

export function artifactsQueryString(query: ArtifactsQuery): string {
  const params = new URLSearchParams();
  if (query.offset) params.set("offset", String(query.offset));
  if (query.limit) params.set("limit", String(query.limit));
  for (const kind of query.kind ?? []) params.append("kind", kind);
  if (query.path_contains?.trim()) params.set("path_contains", query.path_contains.trim());
  for (const type of query.artifact_type ?? []) params.append("artifact_type", type);
  for (const flag of query.flag ?? []) params.append("flag", flag);
  if (query.flag_grade) params.set("flag_grade", query.flag_grade);
  for (const value of query.browser ?? []) params.append("browser", value);
  for (const value of query.service ?? []) params.append("service", value);
  for (const channel of query.channel ?? []) params.append("channel", channel);
  for (const group of query.channel_group ?? []) params.append("channel_group", group);
  for (const [key, value] of Object.entries(query.conditions ?? {})) {
    for (const item of Array.isArray(value) ? value : [value]) params.append(key, item);
  }
  if (query.sort) {
    params.set("sort", query.sort);
    params.set("order", query.order ?? "asc");
    if (query.locate !== undefined) params.set("locate", String(query.locate));
  }
  return params.toString();
}
