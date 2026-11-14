/**
 * Keywords of the top-bar search (R7 S2 #4). The v2 console query takes at most 32 keywords and a
 * 4,000-character query (routes_search_index `MAX_CONSOLE_KEYWORDS`, query.py `MAX_QUERY_CHARS`);
 * beyond that it answered an English validation error. The console trims to the limits itself and
 * says so in Korean, so the search always runs.
 */

export const MAX_SEARCH_KEYWORDS = 32;
export const MAX_SEARCH_KEYWORD_CHARS = 4000;
export const KEYWORD_COUNT_NOTE = `검색어 ${MAX_SEARCH_KEYWORDS}개까지만 사용합니다`;
export const KEYWORD_LENGTH_NOTE = "검색어는 모두 합쳐 4,000자까지만 사용합니다";

export interface ParsedKeywords {
  keywords: string[];
  /** Korean note when keywords were dropped or cut (count and/or length cap). */
  note?: string;
}

/** Split the typed query (spaces / commas), drop duplicates, apply the count and length caps. */
export function parseSearchKeywords(q: string | undefined | null): ParsedKeywords {
  const unique = [...new Set((q ?? "").split(/[\s,]+/).filter(Boolean))];
  const notes: string[] = [];
  let keywords = unique;
  if (keywords.length > MAX_SEARCH_KEYWORDS) {
    keywords = keywords.slice(0, MAX_SEARCH_KEYWORDS);
    notes.push(KEYWORD_COUNT_NOTE);
  }
  let used = 0;
  const kept: string[] = [];
  for (const keyword of keywords) {
    const room = MAX_SEARCH_KEYWORD_CHARS - used;
    if (keyword.length <= room) {
      kept.push(keyword);
      used += keyword.length;
      continue;
    }
    // A single keyword over the cap is cut; later ones that no longer fit are dropped.
    if (kept.length === 0) kept.push(keyword.slice(0, MAX_SEARCH_KEYWORD_CHARS));
    notes.push(KEYWORD_LENGTH_NOTE);
    break;
  }
  return notes.length ? { keywords: kept, note: notes.join(" · ") } : { keywords: kept };
}
