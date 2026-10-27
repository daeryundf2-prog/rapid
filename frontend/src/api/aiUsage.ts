/**
 * AI 사용 (R7 단계 3.5 갈래 D): bounded reads of the `ai-agent` kind's small row types for the
 * 접수 card "AI 사용 요약" and the tree's 도구·설치 views, and the optional server gap report.
 */

import { ApiError, api } from "./client";
import { artifactsQueryString } from "./runs";

const enc = encodeURIComponent;

/** Server page size of `GET /artifacts` (le=1000). */
export const AI_PAGE_SIZE = 1000;

export interface AiRowsPage {
  /** Raw artifact rows (`details` holds the AI fields). */
  rows: Array<Record<string, unknown>>;
  /** Rows of these types in the run (the page total), null when the server did not say. */
  total: number | null;
  /** More rows exist than were read (`maxRows`). */
  truncated: boolean;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** Rows of `types` of the `ai-agent` kind, read page by page up to `maxRows`. */
export async function fetchAiRows(
  runId: string,
  types: readonly string[],
  maxRows: number,
  signal?: AbortSignal,
): Promise<AiRowsPage> {
  const rows: Array<Record<string, unknown>> = [];
  let total: number | null = null;
  for (let offset = 0; offset < maxRows; offset += AI_PAGE_SIZE) {
    const query = artifactsQueryString({
      kind: ["ai-agent"],
      artifact_type: [...types],
      offset,
      limit: Math.min(AI_PAGE_SIZE, maxRows - offset),
    });
    const payload = await api<{ artifacts?: Record<string, Record<string, unknown>> }>(
      `/api/runs/${enc(runId)}/artifacts?${query}`,
      { signal },
    );
    const page = payload.artifacts?.["ai-agent"];
    const list = Array.isArray(page?.artifacts) ? (page.artifacts as Array<Record<string, unknown>>) : [];
    const pagination = (page?.pagination ?? {}) as Record<string, unknown>;
    total =
      asNumber(page?.matched) ??
      asNumber(pagination.matched) ??
      asNumber(page?.total) ??
      asNumber(pagination.total) ??
      total;
    rows.push(...list);
    if (list.length < AI_PAGE_SIZE) return { rows, total: total ?? rows.length, truncated: false };
  }
  return { rows, total, truncated: total === null ? true : total > rows.length };
}

/** One tool of the server's gap table (갈래 C report section "AI 사용"). */
export interface AiGapTool {
  tool: string;
  tool_label?: string;
  local_evidence?: boolean;
  server_evidence_needed?: string[];
}

export interface AiGapReport {
  tools: AiGapTool[];
}

/**
 * Server gap table of the AI usage report section (갈래 C, `GET /api/runs/{id}/ai-usage/gaps`).
 * null when the server has no such endpoint (404 / 405) — the card then computes the gap from the
 * presence and session rows itself.
 */
export const AI_GAP_PATH = "ai-usage/gaps";

export async function fetchAiGapReport(runId: string, signal?: AbortSignal): Promise<AiGapReport | null> {
  try {
    const payload = await api<Record<string, unknown>>(`/api/runs/${enc(runId)}/${AI_GAP_PATH}`, { signal });
    const tools = Array.isArray(payload.tools)
      ? payload.tools
      : Array.isArray(payload.gaps)
        ? payload.gaps
        : null;
    if (!tools) return null;
    return {
      tools: tools
        .filter((item): item is Record<string, unknown> => typeof item === "object" && item !== null)
        .map((item) => ({
          tool: String(item.tool ?? ""),
          ...(typeof item.tool_label === "string" ? { tool_label: item.tool_label } : {}),
          ...(typeof item.local_evidence === "boolean" ? { local_evidence: item.local_evidence } : {}),
          ...(Array.isArray(item.server_evidence_needed)
            ? { server_evidence_needed: item.server_evidence_needed.map(String) }
            : {}),
        }))
        .filter((item) => item.tool),
    };
  } catch (error) {
    if (error instanceof ApiError && (error.status === 404 || error.status === 405)) return null;
    throw error;
  }
}
