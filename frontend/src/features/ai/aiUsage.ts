/**
 * AI 사용 요약 (R7 단계 3.5 갈래 D, plan §3.5): pure aggregation of the `ai-agent` kind's small
 * row types — tools by evidence source, accounts, period, credential files, the tools whose use
 * can only be shown with server-side evidence (no local session store) and the retention markers —
 * plus the 도구·설치 facets of the tree.
 */

import type { AiGapReport } from "../../api/aiUsage";
import { AI_PRESENCE_SOURCE_VIEWS, aiSourceFacet } from "../tree/domains";
import { aiToolName } from "./aiLabels";

type Raw = Record<string, unknown>;

const isRecord = (value: unknown): value is Raw =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export function detailsOf(row: Raw): Raw {
  return isRecord(row.details) ? row.details : {};
}

const text = (value: unknown): string => (typeof value === "string" ? value.trim() : "");

/** Small row types read whole for the summary (presence, credentials, accounts, retention). */
export const AI_SUMMARY_TYPES = [
  "ai-tool-presence",
  "ai-credential-presence",
  "ai-account",
  "ai-account-switch",
  "ai-retention-cleanup",
] as const;

/** Evidence classes of a tool (접수 card "도구 N(실행·설치·세션)"). */
export type AiToolSource = "execution" | "install" | "path" | "session";

export const AI_TOOL_SOURCE_LABELS: Readonly<Record<AiToolSource, string>> = {
  execution: "실행",
  install: "설치",
  path: "경로",
  session: "세션",
};

export interface AiUsageSummary {
  /** Distinct catalog tools seen in any row. */
  tools: number;
  /** Distinct tools per evidence class. */
  toolsBySource: Record<AiToolSource, number>;
  /** Distinct tool accounts (tool + account key / org / e-mail domain hash). */
  accounts: number;
  /** Account switch events (claude-swap log). */
  accountSwitches: number;
  /** First session start / last session end (ISO, UTC) of the sessions read. */
  periodFrom: string | null;
  periodTo: string | null;
  /** Sessions read for the period (fewer than the run's sessions when capped). */
  sessionsRead: number;
  sessionsCapped: boolean;
  /** Credential files (value never collected). */
  credentialFiles: number;
  /** Tools whose use needs server-side evidence: present here, but no local session record. */
  gapTools: string[];
  /** Where the gap came from: the server's report section, or the console's own reading. */
  gapSource: "server" | "computed";
  /** Retention markers (`ai-retention-cleanup`) and tools with a retention period on record. */
  retentionMarkers: number;
  retentionTools: string[];
  /** The smallest retention period in days on record, null when none. */
  minRetentionDays: number | null;
  /** Some rows were not read (more rows than the summary reads). */
  truncated: boolean;
}

function sourceClass(details: Raw): AiToolSource | null {
  const source = text(details.source);
  const kind = text(details.install_kind);
  if (source.startsWith("execution:") || kind === "execution") return "execution";
  if (source.startsWith("install:") || (kind && kind !== "path")) return "install";
  if (source === "catalog-path" || kind === "path") return "path";
  return null;
}

function toolOf(details: Raw): string {
  return text(details.tool);
}

function numberOf(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() && Number.isFinite(Number(value))) return Number(value);
  return null;
}

/** 도구·설치 facets (`rowFacets["ai-agent"]`): presence rows per source view. */
export function presenceFacets(rows: readonly Raw[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const view of AI_PRESENCE_SOURCE_VIEWS) out[aiSourceFacet(view.source)] = 0;
  for (const row of rows) {
    if (row.artifact_type !== "ai-tool-presence") continue;
    const source = text(detailsOf(row).source);
    for (const view of AI_PRESENCE_SOURCE_VIEWS) {
      if (source.includes(view.source)) {
        const key = aiSourceFacet(view.source);
        out[key] = (out[key] ?? 0) + 1;
      }
    }
  }
  return out;
}

/** Display name of a tool id (catalog name, else the id as written). */
export function aiToolTitle(tool: string, labels?: ReadonlyMap<string, string>): string {
  return labels?.get(tool) || aiToolName(tool) || tool;
}

export function summarizeAiUsage(input: {
  rows: readonly Raw[];
  sessions: readonly Raw[];
  sessionsCapped?: boolean;
  truncated?: boolean;
  gap?: AiGapReport | null;
}): AiUsageSummary {
  const tools = new Set<string>();
  const bySource: Record<AiToolSource, Set<string>> = {
    execution: new Set(),
    install: new Set(),
    path: new Set(),
    session: new Set(),
  };
  const accounts = new Set<string>();
  const local = new Set<string>();
  const retentionTools = new Set<string>();
  let switches = 0;
  let credentials = 0;
  let markers = 0;
  let minDays: number | null = null;
  const noteDays = (value: unknown) => {
    const days = numberOf(value);
    if (days !== null && days > 0) minDays = minDays === null ? days : Math.min(minDays, days);
  };
  for (const row of input.rows) {
    const type = text(row.artifact_type);
    const details = detailsOf(row);
    const tool = toolOf(details);
    if (tool) tools.add(tool);
    if (type === "ai-tool-presence") {
      const cls = sourceClass(details);
      if (tool && cls) bySource[cls].add(tool);
      if (tool && details.retention_auto_delete === true) retentionTools.add(tool);
      noteDays(details.retention_days);
    } else if (type === "ai-credential-presence") {
      credentials += 1;
    } else if (type === "ai-account") {
      const key =
        text(details.tool_account_key) ||
        [
          text(details.org_key || details.org_label),
          text(details.email_domain),
          text(details.email_local_hash),
        ]
          .filter(Boolean)
          .join("|");
      accounts.add(`${tool}::${key || text(row.path)}`);
    } else if (type === "ai-account-switch") {
      switches += 1;
    } else if (type === "ai-retention-cleanup") {
      markers += 1;
      if (tool) retentionTools.add(tool);
      noteDays(details.retention_days);
    }
  }
  let from: string | null = null;
  let to: string | null = null;
  const earlier = (a: string | null, b: string) => (a === null || Date.parse(b) < Date.parse(a) ? b : a);
  const later = (a: string | null, b: string) => (a === null || Date.parse(b) > Date.parse(a) ? b : a);
  for (const row of input.sessions) {
    const details = detailsOf(row);
    const tool = toolOf(details);
    if (tool) {
      tools.add(tool);
      bySource.session.add(tool);
      local.add(tool);
    }
    const start = text(details.started_at) || text(details.timestamp);
    const end = text(details.ended_at) || start;
    if (start && !Number.isNaN(Date.parse(start))) from = earlier(from, start);
    if (end && !Number.isNaN(Date.parse(end))) to = later(to, end);
  }
  const gapFromServer = input.gap?.tools.length ? input.gap : null;
  const gapTools = gapFromServer
    ? gapFromServer.tools.filter((item) => item.local_evidence !== true).map((item) => item.tool)
    : // Tools present here (paths, installs, executions, credentials, accounts) with no session
      // record: what they were used for can only be shown with the vendor's / organisation's records.
      [...tools].filter((tool) => !local.has(tool));
  return {
    tools: tools.size,
    toolsBySource: {
      execution: bySource.execution.size,
      install: bySource.install.size,
      path: bySource.path.size,
      session: bySource.session.size,
    },
    accounts: accounts.size,
    accountSwitches: switches,
    periodFrom: from,
    periodTo: to,
    sessionsRead: input.sessions.length,
    sessionsCapped: Boolean(input.sessionsCapped),
    credentialFiles: credentials,
    gapTools: gapTools.sort((a, b) => aiToolTitle(a).localeCompare(aiToolTitle(b), "ko")),
    gapSource: gapFromServer ? "server" : "computed",
    retentionMarkers: markers,
    retentionTools: [...retentionTools].sort(),
    minRetentionDays: minDays,
    truncated: Boolean(input.truncated),
  };
}
