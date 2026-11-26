/**
 * Search text ⇄ searches (plan search-2026-10-13 §4 `queryModel`).
 *
 * The routed `q` is the one source of truth for what the search grid shows. It is read as a list
 * of searches (the chips) plus how they combine; the server stays the only interpreter of each
 * search's own grammar. Plain words keep the scan search's meaning: every word is its own
 * search and a row matches when any of them does. A text that uses the grammar (an operator, a
 * `field:` clause) is one search, read by the server as written.
 */

import type { CollectionQuery } from "../../contracts/collection";

/** How several searches show together: `any` = a row of any search, `all` = rows every search matches. */
export type SearchCombine = "any" | "all";

export interface SearchSelection {
  readonly searches: readonly string[];
  readonly combine: SearchCombine;
}

type SearchSpec = NonNullable<CollectionQuery["search"]>;

const OPERATORS: ReadonlySet<string> = new Set(["AND", "OR", "NOT"]);
/** `field:value` of the query grammar (`in:eventlog`, `data.LogonType:10`); not a URL or a drive path. */
const FIELD_CLAUSE = /^[a-z][a-z0-9_.]*:(?!\/\/|\\)/;

/** Pieces of a query text split at spaces and commas outside "…", (…), […] and /…/. */
function topLevelTokens(text: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let depth = 0;
  let quoted = false;
  let regex = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index] ?? "";
    if (quoted) {
      current += char;
      quoted = char !== '"';
      continue;
    }
    if (regex) {
      current += char;
      if (char === "\\") {
        current += text[index + 1] ?? "";
        index += 1;
      } else if (char === "/") regex = false;
      continue;
    }
    if (depth === 0 && (char === "," || /\s/.test(char))) {
      if (current) tokens.push(current);
      current = "";
      continue;
    }
    if (char === '"') quoted = true;
    else if (char === "/" && (current === "" || current.endsWith(":"))) regex = true;
    else if (char === "(" || char === "[") depth += 1;
    else if ((char === ")" || char === "]") && depth > 0) depth -= 1;
    current += char;
  }
  if (current) tokens.push(current);
  return tokens;
}

/** Inner text when `token` is exactly one parenthesised group: "(a b)" → "a b"; else null. */
function unwrapGroup(token: string): string | null {
  if (!token.startsWith("(") || !token.endsWith(")")) return null;
  let depth = 0;
  for (let index = 0; index < token.length; index += 1) {
    if (token[index] === "(") depth += 1;
    else if (token[index] === ")") {
      depth -= 1;
      if (depth === 0 && index < token.length - 1) return null;
    }
  }
  const inner = token.slice(1, -1).trim();
  return depth === 0 && inner ? inner : null;
}

/** `(a) OR (b)` / `(a) AND (b)`, the form `combineSearches` writes, read back into its searches. */
function groupedSelection(tokens: readonly string[]): SearchSelection | null {
  const operator = tokens[1];
  if (tokens.length % 2 === 0 || (operator !== undefined && operator !== "AND" && operator !== "OR")) {
    return null;
  }
  const searches: string[] = [];
  for (const [index, token] of tokens.entries()) {
    if (index % 2 === 1) {
      if (token !== operator) return null;
      continue;
    }
    const inner = unwrapGroup(token);
    if (inner === null) return null;
    searches.push(inner);
  }
  return { searches: [...new Set(searches)], combine: operator === "AND" ? "all" : "any" };
}

/** The searches a query text stands for. A text that uses the grammar stays one search. */
export function parseSearchInput(text: string): SearchSelection {
  const tokens = topLevelTokens(text);
  if (tokens.length === 0) return { searches: [], combine: "any" };
  const grouped = groupedSelection(tokens);
  if (grouped) return grouped;
  if (tokens.some((token) => OPERATORS.has(token) || token.startsWith("-") || FIELD_CLAUSE.test(token))) {
    return { searches: [text.trim()], combine: "any" };
  }
  return { searches: [...new Set(tokens)], combine: "any" };
}

/** The query text of a selection; `parseSearchInput` reads it back to the same selection. */
export function combineSearches(searches: readonly string[], combine: SearchCombine): string {
  const [only] = searches;
  if (searches.length === 1 && only !== undefined) {
    const parsed = parseSearchInput(only);
    return parsed.searches.length === 1 && parsed.searches[0] === only ? only : `(${only})`;
  }
  return searches.map((search) => `(${search})`).join(combine === "all" ? " AND " : " OR ");
}

/** Rows of `search` that no search in `others` matches. */
export function onlyQuery(search: string, others: readonly string[]): string {
  return others.length ? `(${search}) AND NOT (${combineSearches(others, "any")})` : search;
}

/** The grid's search spec for a selection under the search options (mode, sources, known-good). */
export function searchSpecOf(
  selection: SearchSelection,
  options: {
    readonly mode: SearchSpec["mode"];
    readonly sources: readonly string[];
    readonly hideKnownGood: boolean;
  },
): SearchSpec {
  return {
    keywords: [...selection.searches],
    combine: selection.combine,
    mode: options.mode,
    sources: options.sources.length ? [...options.sources] : undefined,
    hideKnownGood: options.hideKnownGood,
  };
}

/** Scan-search sources the index can scope to (`in:`), by their index collection. */
const INDEX_COLLECTIONS: Readonly<Record<string, string>> = {
  documents: "docs",
  files: "files",
  artifacts: "artifacts",
  indicators: "indicators",
};

/** Where a search runs: the run's index, or the bounded scan when an option only the scan has is on. */
export type SearchPlan =
  | { readonly kind: "index"; readonly q: string }
  | { readonly kind: "scan"; readonly reason: string };

export function searchPlan(spec: SearchSpec, extensions: readonly string[] = []): SearchPlan {
  if (spec.mode !== "exact") {
    return { kind: "scan", reason: "유사 일치·정규식 방식은 색인 대신 원본을 스캔합니다." };
  }
  if (spec.hideKnownGood) {
    return { kind: "scan", reason: "known-good 숨기기는 원본 스캔에서만 적용됩니다." };
  }
  const collections: string[] = [];
  for (const source of spec.sources ?? []) {
    const collection = INDEX_COLLECTIONS[source];
    if (collection === undefined) {
      return { kind: "scan", reason: "선택한 검색 범위는 색인 대신 원본을 스캔합니다." };
    }
    collections.push(collection);
  }
  const scope = [
    ...(collections.length ? [`in:(${collections.join(", ")})`] : []),
    ...(extensions.length ? [`ext:(${extensions.map((ext) => ext.replace(/^\./, "")).join(", ")})`] : []),
  ];
  const q = combineSearches(spec.keywords, spec.combine ?? "any");
  return { kind: "index", q: scope.length ? `(${q}) AND ${scope.join(" AND ")}` : q };
}
