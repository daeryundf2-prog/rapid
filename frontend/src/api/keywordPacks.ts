import { api } from "./client";

export interface KeywordPack {
  name: string;
  label?: string;
  description?: string;
  keyword_count?: number;
  [key: string]: unknown;
}

export async function listKeywordPacks(): Promise<KeywordPack[]> {
  const payload = await api<{ packs: KeywordPack[] }>("/api/keyword-packs");
  return Array.isArray(payload.packs) ? payload.packs : [];
}

/** Options accepted by `GET /api/runs/{id}/search` (see routes_search.py). */
export interface SearchOptions {
  mode: "exact" | "fuzzy" | "regex";
  sources: string[];
  extensions: string[];
  pathContains: string;
  fuzzyDistance: number;
  proximityWindow: number;
  ocr: boolean;
  hideKnownGood: boolean;
  keywordPacks: string[];
  limit: number;
}

export const DEFAULT_SEARCH_OPTIONS: SearchOptions = {
  mode: "exact",
  sources: [],
  extensions: [],
  pathContains: "",
  fuzzyDistance: 1,
  proximityWindow: 0,
  // OCR sidecars are opt-in (R7): reading them costs every search 0.3-0.7 s on a real run.
  ocr: false,
  hideKnownGood: false,
  keywordPacks: [],
  limit: 500,
};

/** Search sources the unified search understands. */
export const SEARCH_SOURCES: Array<{ id: string; label: string }> = [
  { id: "documents", label: "문서" },
  { id: "files", label: "파일" },
  { id: "artifacts", label: "아티팩트" },
  { id: "timeline", label: "타임라인" },
  { id: "indicators", label: "지표" },
];

/** Query string for `GET /api/runs/{id}/search` (keyword[] is repeated; empty values omitted). */
export function searchQueryString(keywords: string[], options: SearchOptions): string {
  const params = new URLSearchParams();
  for (const keyword of keywords) params.append("keyword", keyword);
  params.set("search_mode", options.mode);
  params.set("ocr", String(options.ocr));
  params.set("limit", String(options.limit));
  for (const source of options.sources) params.append("source", source);
  for (const extension of options.extensions) params.append("extension", extension);
  if (options.pathContains.trim()) params.set("path_contains", options.pathContains.trim());
  if (options.mode === "fuzzy") params.set("fuzzy_distance", String(options.fuzzyDistance));
  if (options.proximityWindow > 0) params.set("proximity_window", String(options.proximityWindow));
  if (options.hideKnownGood) params.set("hide_known_good", "true");
  for (const pack of options.keywordPacks) params.append("keyword_pack", pack);
  return params.toString();
}

export function searchPath(runId: string, keywords: string[], options: SearchOptions): string {
  return `/api/runs/${encodeURIComponent(runId)}/search?${searchQueryString(keywords, options)}`;
}
