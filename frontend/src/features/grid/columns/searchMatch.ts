/**
 * Search hit reading (F11): where a keyword matched (본문 / 이름 / 경로 / 메타) and the text
 * around the hit (±40 characters, hit marked), from the hit's own fields — never the server's
 * `preview` when that is a cut JSON dump of the record (artifact and timeline hits,
 * core/search.py `compact_json_preview`). A timeline hit's 본문 is its event's summary.
 */

import { baseName, isRecord, str } from "./common";

export type MatchField = "body" | "name" | "path" | "meta";

export const MATCH_FIELD_LABELS: Readonly<Record<MatchField, string>> = {
  body: "본문",
  name: "이름",
  path: "경로",
  meta: "메타",
};

/** Display order of the matched fields ("본문, 경로"). */
const FIELD_ORDER: readonly MatchField[] = ["body", "name", "path", "meta"];
/** Which field's text the context comes from first: the path holds the name and its folders. */
const CONTEXT_ORDER: readonly MatchField[] = ["body", "path", "name", "meta"];

/** Characters kept on each side of the hit. */
export const CONTEXT_RADIUS = 40;

export interface MatchContext {
  field: MatchField;
  before: string;
  hit: string;
  after: string;
  /** Text was cut before `before` / after `after` ("…"). */
  cutStart: boolean;
  cutEnd: boolean;
}

export interface SearchMatch {
  /** Every field a keyword was found in, FIELD_ORDER. */
  fields: MatchField[];
  context: MatchContext | null;
}

type Finder = (text: string) => { index: number; length: number } | null;

/**
 * A finder for the keywords that matched: case-insensitive text (exact / fuzzy mode — a fuzzy
 * hit that is not literally present simply has no context), or each keyword as a regular
 * expression in regex mode (an invalid one falls back to text).
 */
export function keywordFinder(keywords: readonly string[], mode: string): Finder {
  const words = keywords.map((word) => word.normalize("NFC").trim()).filter(Boolean);
  const patterns: RegExp[] = [];
  for (const word of words) {
    if (mode === "regex") {
      try {
        patterns.push(new RegExp(word, "iu"));
        continue;
      } catch {
        // not a valid expression: match it as text
      }
    }
    patterns.push(new RegExp(word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "iu"));
  }
  return (text) => {
    let best: { index: number; length: number } | null = null;
    for (const pattern of patterns) {
      const found = pattern.exec(text);
      if (found && found[0].length > 0 && (best === null || found.index < best.index))
        best = { index: found.index, length: found[0].length };
    }
    return best;
  };
}

/** A JSON object / array dump (the server's record preview), not readable text. */
export function looksLikeJson(text: string): boolean {
  return /^\s*[[{]/.test(text);
}

function isLowSurrogate(code: number): boolean {
  return code >= 0xdc00 && code <= 0xdfff;
}

/** `text` around the first hit, ±`radius` characters, whitespace collapsed; null without a hit. */
export function contextAround(
  text: string,
  find: Finder,
  field: MatchField,
  radius = CONTEXT_RADIUS,
): MatchContext | null {
  // NFC like the server's normalize_search_text (review P3-3): a macOS NFD name matches.
  const flat = text.normalize("NFC").replace(/\s+/g, " ").trim();
  const hit = find(flat);
  if (!hit) return null;
  let start = Math.max(0, hit.index - radius);
  let end = Math.min(flat.length, hit.index + hit.length + radius);
  // Never cut a surrogate pair (review P3-2): widen by one unit at either edge.
  if (start > 0 && isLowSurrogate(flat.charCodeAt(start))) start -= 1;
  if (end < flat.length && isLowSurrogate(flat.charCodeAt(end))) end += 1;
  return {
    field,
    before: flat.slice(start, hit.index),
    hit: flat.slice(hit.index, hit.index + hit.length),
    after: flat.slice(hit.index + hit.length, end),
    cutStart: start > 0,
    cutEnd: end < flat.length,
  };
}

/** Record keys that repeat the query or the search bookkeeping, never a 메타 hit of their own. */
const META_SKIP: Readonly<Record<string, true>> = {
  matched_keywords: true,
  matched: true,
  keywords: true,
  search_match: true,
  path: true,
  summary: true,
  // The hit's own name / title are its 이름 / 항목, not a 메타 hit.
  name: true,
  title: true,
};

/** String leaves of a record (depth-limited), skipping META_SKIP keys. */
function metaStrings(value: unknown, out: string[], depth = 0): void {
  if (depth > 4 || out.length > 400) return;
  if (typeof value === "string") {
    if (value.trim()) out.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) metaStrings(item, out, depth + 1);
  } else if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) if (!META_SKIP[key]) metaStrings(item, out, depth + 1);
  }
}

/** The searchable texts of a hit per field (`GET /search` match row). */
export function searchHitTexts(raw: Record<string, unknown>): Record<MatchField, string[]> {
  const source = str(raw.source);
  const metadata = isRecord(raw.metadata) ? raw.metadata : {};
  const path = str(raw.path);
  const preview = str(raw.preview);
  const body: string[] = [];
  const name: string[] = [];
  if (source === "timeline") body.push(str(metadata.summary) || str(raw.title));
  else if (source === "indicators") body.push(str(raw.title));
  if (preview && !looksLikeJson(preview) && preview !== path) body.push(preview);
  // Files, documents and OCR hits are named by their file; an artifact by its file too.
  if (source !== "timeline" && source !== "indicators") {
    const own = str(metadata.name) || baseName(path);
    if (own) name.push(own);
  }
  const meta: string[] = [];
  metaStrings(metadata, meta);
  return { body: body.filter(Boolean), name, path: path ? [path] : [], meta };
}

/** Where the hit's keywords matched and the context around the first readable hit. */
export function searchMatch(raw: Record<string, unknown>): SearchMatch {
  const keywords = Array.isArray(raw.matched_keywords) ? raw.matched_keywords.map(str) : [];
  const searchInfo = isRecord(raw.search_match) ? raw.search_match : {};
  const find = keywordFinder(keywords, str(searchInfo.mode));
  const texts = searchHitTexts(raw);
  const contexts = new Map<MatchField, MatchContext>();
  for (const field of FIELD_ORDER) {
    for (const text of texts[field]) {
      const context = contextAround(text, find, field);
      if (context) {
        contexts.set(field, context);
        break;
      }
    }
  }
  const fields = FIELD_ORDER.filter((field) => contexts.has(field));
  const first = CONTEXT_ORDER.find((field) => contexts.has(field));
  return { fields, context: first ? (contexts.get(first) ?? null) : null };
}

/** Plain text of a context ("…before hit after…"): the cell's value, copy and filter text. */
export function contextText(context: MatchContext | null): string {
  if (!context) return "";
  return `${context.cutStart ? "…" : ""}${context.before}${context.hit}${context.after}${context.cutEnd ? "…" : ""}`;
}
