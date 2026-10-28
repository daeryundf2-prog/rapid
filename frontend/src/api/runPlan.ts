// Run plan (처리 계획표, R4 V1 / plan run-model-p2 §3.4): the group → task table of a run,
// its controls (cancel / skip / cancel_all / finish) and the pre-run group preview.

import { useQuery } from "@tanstack/react-query";
import { ApiError, api, authToken, errorMessageFromDetail } from "./client";
import { normalizeRunStatus } from "./runs";

export { type RetryOptions, type RetryResult, retryRun } from "./runControl";

export type TaskStatus = "queued" | "running" | "completed" | "partial" | "failed" | "skipped" | "cancelled";

export const TASK_STATUSES: readonly TaskStatus[] = [
  "queued",
  "running",
  "completed",
  "partial",
  "failed",
  "skipped",
  "cancelled",
];

/** Terminal task / group states (nothing left to run). */
export const FINISHED_TASK_STATUSES: ReadonlySet<string> = new Set([
  "completed",
  "partial",
  "failed",
  "skipped",
  "cancelled",
]);

export interface PlanCounts {
  total: number;
  queued: number;
  running: number;
  completed: number;
  partial: number;
  failed: number;
  skipped: number;
  cancelled: number;
}

export interface PlanRequester {
  actor?: "web" | "cli" | string;
  at?: string;
}

export interface PlanTask {
  id: string;
  group: string;
  label: string;
  type?: "provider" | "stage" | string;
  status: TaskStatus | string;
  reused?: boolean;
  queued_order?: number | null;
  started_at?: string | null;
  finished_at?: string | null;
  duration_ms?: number | null;
  artifact_count?: number | null;
  rows_so_far?: number | null;
  output?: { path?: string; records_path?: string } | null;
  message?: string;
  /** Korean reason of a skipped / cancelled / partial task ("분석관 요청", "마치기 요청" …). */
  reason?: string | null;
  requested_by?: PlanRequester | null;
  parser_error_count?: number;
  skippable?: boolean;
}

export interface PlanGroup {
  id: string;
  label: string;
  status: TaskStatus | string;
  skippable: boolean;
  counts: PlanCounts;
  started_at?: string | null;
  finished_at?: string | null;
  duration_ms?: number | null;
  artifact_count?: number | null;
  tasks: PlanTask[];
}

export type PlanOutcome = "complete" | "partial" | "cancelled" | "interrupted" | null;

export type PlanControlAction = "cancel" | "skip" | "cancel_all" | "finish";

export type PlanTarget = { group: string } | { task: string };

export interface PlanControlRequest {
  seq?: number;
  action: PlanControlAction | string;
  targets?: PlanTarget[];
  actor?: string;
  at?: string;
}

export interface RunPlan {
  command?: string;
  version?: string;
  run_id: string;
  run_status: string;
  /** The run process is alive (fresh heartbeat, owner alive). */
  live?: boolean;
  /** Running but the heartbeat is older than 90 s ("응답 없음"). */
  stale?: boolean;
  heartbeat_at?: string | null;
  elapsed_ms?: number | null;
  run_root?: string;
  mode?: string;
  options?: {
    carve?: boolean;
    extract?: boolean;
    case_db?: boolean;
    skip_groups?: string[];
    skip_tasks?: string[];
  };
  outcome?: PlanOutcome | string;
  control?: {
    cancel_all_at?: string | null;
    finish_at?: string | null;
    requests?: PlanControlRequest[];
  };
  counts: { groups: PlanCounts; tasks: PlanCounts };
  groups: PlanGroup[];
  started_at?: string | null;
  updated_at?: string | null;
}

export interface PlanControlResult {
  accepted: PlanTarget[];
  rejected: Array<{ target: PlanTarget | Record<string, unknown>; reason: string }>;
  plan: RunPlan;
}

export interface PreviewGroup {
  id: string;
  label: string;
  default_on: boolean;
  skippable: boolean;
  tasks: Array<{ id: string; label: string }>;
}

export interface RunPlanPreview {
  mode: string;
  groups: PreviewGroup[];
}

export interface PreviewQuery {
  mode: string;
  carve?: boolean;
  extract?: boolean;
  case_db?: boolean;
  input_kind?: string | null;
}

const enc = encodeURIComponent;

/** Last plan + ETag per run: `If-None-Match` lets an unchanged plan answer 304. */
const etagCache = new Map<string, { etag: string; plan: RunPlan }>();

/** Test hook: forget cached ETags. */
export function resetRunPlanCache(): void {
  etagCache.clear();
}

/** `GET /api/runs/{id}/plan` (304 → the cached plan). Statuses are normalized (`canceled` → `cancelled`). */
export async function getRunPlan(runId: string): Promise<RunPlan> {
  const token = authToken();
  const cached = etagCache.get(runId);
  const response = await fetch(`/api/runs/${enc(runId)}/plan`, {
    headers: {
      ...(token ? { "X-RapidTriage-Token": token } : {}),
      ...(cached ? { "If-None-Match": cached.etag } : {}),
    },
  });
  if (response.status === 304 && cached) return cached.plan;
  if (!response.ok) {
    const detail = await response.json().catch(() => ({ detail: response.statusText }));
    const raw = (detail as { detail?: unknown }).detail ?? detail;
    throw new ApiError(errorMessageFromDetail(raw), response.status, raw);
  }
  const plan = normalizePlan((await response.json()) as RunPlan);
  const etag = response.headers?.get?.("etag");
  if (etag) etagCache.set(runId, { etag, plan });
  else etagCache.delete(runId);
  return plan;
}

/** `POST /api/runs/{id}/plan/control` — 202 with accepted / rejected targets and the new plan. */
export async function controlRunPlan(
  runId: string,
  action: PlanControlAction,
  targets?: PlanTarget[],
): Promise<PlanControlResult> {
  const body: { action: PlanControlAction; targets?: PlanTarget[] } = { action };
  if (targets?.length) body.targets = targets;
  const result = await api<PlanControlResult>(`/api/runs/${enc(runId)}/plan/control`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  etagCache.delete(runId);
  return {
    accepted: result.accepted ?? [],
    rejected: result.rejected ?? [],
    plan: normalizePlan(result.plan),
  };
}

/** `GET /api/run-plan/preview?mode=…` — the groups a new run would plan (defaults = `default_on`). */
export function previewRunPlan(query: PreviewQuery): Promise<RunPlanPreview> {
  const params = new URLSearchParams();
  params.set("mode", query.mode);
  if (query.carve !== undefined) params.set("carve", String(query.carve));
  if (query.extract !== undefined) params.set("extract", String(query.extract));
  if (query.case_db !== undefined) params.set("case_db", String(query.case_db));
  if (query.input_kind !== undefined && query.input_kind !== null) params.set("input_kind", query.input_kind);
  return api<RunPlanPreview>(`/api/run-plan/preview?${params.toString()}`);
}

const EMPTY_COUNTS: PlanCounts = {
  total: 0,
  queued: 0,
  running: 0,
  completed: 0,
  partial: 0,
  failed: 0,
  skipped: 0,
  cancelled: 0,
};

function countsOf(raw: Partial<PlanCounts> | undefined): PlanCounts {
  const counts = { ...EMPTY_COUNTS, ...(raw ?? {}) };
  const legacy = (raw as Record<string, unknown> | undefined)?.canceled;
  if (typeof legacy === "number") counts.cancelled += legacy;
  return counts;
}

/** One spelling of every status in a plan (old files: `canceled`), and complete count blocks. */
export function normalizePlan(plan: RunPlan): RunPlan {
  return {
    ...plan,
    run_status: normalizeRunStatus(plan.run_status),
    outcome: plan.outcome ? normalizeRunStatus(plan.outcome) : (plan.outcome ?? null),
    counts: { groups: countsOf(plan.counts?.groups), tasks: countsOf(plan.counts?.tasks) },
    groups: (plan.groups ?? []).map((group) => ({
      ...group,
      status: normalizeRunStatus(group.status),
      counts: countsOf(group.counts),
      tasks: (group.tasks ?? []).map((task) => ({ ...task, status: normalizeRunStatus(task.status) })),
    })),
  };
}

/** Run states the plan is polled in (every 1.5 s, like the runs list). */
export function isPlanPolling(status: unknown): boolean {
  const value = normalizeRunStatus(status);
  return value === "queued" || value === "running";
}

export const PLAN_POLL_MS = 1500;

export const runPlanQueryKey = (runId: string | null) => ["run-plan", runId] as const;

/**
 * The run plan of `runId`, polled every 1.5 s while the run (or the plan itself) is queued /
 * running. A 404 (run without a plan: written before R4) leaves `data` undefined.
 */
export function useRunPlan(runId: string | null, runStatus: unknown) {
  return useQuery({
    queryKey: runPlanQueryKey(runId),
    queryFn: () => getRunPlan(runId as string),
    enabled: Boolean(runId),
    retry: false,
    refetchInterval: (query) => {
      // A server without plans (404) is not asked again every 1.5 s.
      const error = query.state.error;
      if (error instanceof ApiError && error.status === 404) return false;
      return isPlanPolling(runStatus) || isPlanPolling(query.state.data?.run_status) ? PLAN_POLL_MS : false;
    },
  });
}
