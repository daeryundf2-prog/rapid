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
  children?: TreeNode[];
}

export interface RunTree {
  run_id: string;
  root: { label?: string; mode?: string; status?: string };
  nodes: TreeNode[];
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
