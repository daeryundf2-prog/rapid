/**
 * 계열·중복·예외 항목 API (R7 갈래 A): one item's family (`GET /families/{ref}`), the selection
 * expansion (`GET /family-expansion`), and the dedup / irregular summaries. Every route is a
 * read-only GET over the run's derivation (built on the first request).
 */

import type { RowRef } from "../contracts/rowRef";
import { api } from "./client";

const run = (runId: string) => `/api/runs/${encodeURIComponent(runId)}`;

/** Collections whose rows have item refs (`<collection>:<kind>:<locator>`). */
export const FAMILY_COLLECTIONS: readonly string[] = ["artifacts", "files", "analysis"];

/** The item ref of a row ref (`artifacts:email:/artifacts/3`), or null for other collections. */
export function itemRef(ref: Pick<RowRef, "collection" | "kind" | "locator">): string | null {
  if (!FAMILY_COLLECTIONS.includes(ref.collection)) return null;
  if (ref.collection === "files") {
    return /^\/(candidates|inventory)\/\d+$/.test(ref.locator) ? `files::${ref.locator}` : null;
  }
  if (!ref.kind) return null;
  if (ref.collection === "analysis")
    return /^\/rows\/\d+$/.test(ref.locator) ? `analysis:${ref.kind}:${ref.locator}` : null;
  return /^\/artifacts\/\d+(#(entry|attachment):\d+)?$/.test(ref.locator)
    ? `artifacts:${ref.kind}:${ref.locator}`
    : null;
}

/** `{collection, kind, locator}` of an item ref; null when malformed. */
export function parseItemRef(text: string): { collection: string; kind: string; locator: string } | null {
  const first = text.indexOf(":");
  const second = first >= 0 ? text.indexOf(":", first + 1) : -1;
  if (first < 0 || second < 0) return null;
  const collection = text.slice(0, first);
  const kind = text.slice(first + 1, second);
  const locator = text.slice(second + 1);
  if (!["artifacts", "files", "analysis", "source"].includes(collection) || !locator) return null;
  return { collection, kind, locator };
}

/** The row ref an item ref names (virtual entries: their row), or null (source files are no rows). */
export function rowRefOfItem(text: string): RowRef | null {
  const parsed = parseItemRef(text);
  if (!parsed || parsed.collection === "source") return null;
  const locator = parsed.locator.replace(/#(entry|attachment):\d+$/, "");
  if (parsed.collection === "files") return { collection: "files", locator };
  return { collection: parsed.collection as RowRef["collection"], kind: parsed.kind, locator };
}

export interface FamilyNode {
  ref: string;
  collection: string;
  kind: string;
  locator: string;
  title: string;
  artifact_type: string;
  relation: string | null;
  relation_label: string | null;
  material: boolean;
  virtual: boolean;
  navigable: boolean;
  row_ref: string | null;
  children: number;
  /** `<zip>::<entry>` preview path of a ZIP entry (when the caller named the archive's path). */
  source_path?: string;
  /** Tree nodes only. */
  items?: FamilyNode[];
  truncated?: boolean;
}

export interface FamilyResponse {
  ref: string;
  direction: "up" | "down" | "family";
  has_family: boolean;
  item: FamilyNode;
  parent: FamilyNode | null;
  top: FamilyNode;
  is_top: boolean;
  ancestors?: FamilyNode[];
  siblings?: FamilyNode[];
  tree?: FamilyNode;
  tree_truncated?: boolean;
  counts?: { members: number; descendants: number; material: number; rows: number };
}

export function fetchFamily(
  runId: string,
  ref: string,
  options: { direction?: "up" | "down" | "family"; sourcePath?: string | null; signal?: AbortSignal } = {},
): Promise<FamilyResponse> {
  const params = new URLSearchParams({ direction: options.direction ?? "family" });
  if (options.sourcePath) params.set("source_path", options.sourcePath);
  return api<FamilyResponse>(`${run(runId)}/families/${encodeURIComponent(ref)}?${params}`, {
    signal: options.signal,
  });
}

export interface FamilyExpansion {
  requested: number;
  added: number;
  count: number;
  items: { ref: string; collection: string; kind: string; locator: string }[];
}

export function fetchFamilyExpansion(
  runId: string,
  refs: readonly string[],
  signal?: AbortSignal,
): Promise<FamilyExpansion> {
  const params = new URLSearchParams();
  for (const ref of refs) params.append("ref", ref);
  return api<FamilyExpansion>(`${run(runId)}/family-expansion?${params}`, { signal });
}

export interface IrregularCategory {
  id: string;
  label: string;
  help: string;
  count: number;
  files: number;
  candidates: number;
  inventory: number;
  artifacts: number;
}

export interface IrregularSummary {
  categories: IrregularCategory[];
  total: number;
  unique_items: number;
  /** Rows in at least one category, per list (what `irregular=<every id>` lists there). */
  unique_by_list?: { candidates: number; inventory: number; artifacts: number };
  source?: string;
}

export function fetchIrregularSummary(runId: string, signal?: AbortSignal): Promise<IrregularSummary> {
  return api<IrregularSummary>(`${run(runId)}/irregular/summary`, { signal });
}

export interface DedupModeSummary {
  id: "item" | "family" | "custodian";
  label: string;
  items: number;
  groups: number;
  originals: number;
  duplicates: number;
  groups_with_duplicates: number;
}

export interface DedupSummary {
  modes: DedupModeSummary[];
  custodians_assigned: boolean;
  source?: string;
}

export function fetchDedupSummary(runId: string, signal?: AbortSignal): Promise<DedupSummary> {
  return api<DedupSummary>(`${run(runId)}/dedup/summary`, { signal });
}
