import { create } from "zustand";
import type { SavedSearch } from "../../api/caseDb";
import { DEFAULT_SEARCH_OPTIONS, type SearchOptions } from "../../api/keywordPacks";
import { readStoredJson, writeStored } from "../../state/storage";

const RECENT_KEY = "rapidtriage.search.recent";
/** Searches kept as chips per run; the oldest ones outside the newest search go first. */
export const MAX_RECENT_SEARCHES = 12;
/** Runs whose chips are kept. */
const MAX_RECENT_RUNS = 20;

type RecentSearches = Record<string, string[]>;

function isRecentSearches(value: unknown): value is RecentSearches {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.values(value).every(
      (list) => Array.isArray(list) && list.every((item) => typeof item === "string"),
    )
  );
}

/**
 * Search options + the keywords the top-bar search (S1) is about to run.
 * The options popover writes here; S1's search input reads `options` when it
 * builds the request with `searchPath()` / `searchQueryString()`.
 */
interface SearchState {
  keywords: string[];
  options: SearchOptions;
  popoverOpen: boolean;
  /** Searches run on each run, kept as chips (this browser; plan search §4 "최근 검색"), oldest first. */
  recent: RecentSearches;
  setKeywords: (keywords: string[]) => void;
  patchOptions: (patch: Partial<SearchOptions>) => void;
  resetOptions: () => void;
  setPopoverOpen: (open: boolean) => void;
  /** Load a saved search into the state (keywords + sources + limit). */
  applySaved: (search: SavedSearch) => void;
  /** Keep the searches just shown as chips of the run (order of first use). */
  rememberSearches: (runId: string, searches: readonly string[]) => void;
  forgetSearch: (runId: string, search: string) => void;
}

function withRun(recent: RecentSearches, runId: string, list: string[]): RecentSearches {
  const { [runId]: _previous, ...others } = recent;
  const kept = Object.entries(others).slice(-(MAX_RECENT_RUNS - 1));
  const next = Object.fromEntries(list.length ? [...kept, [runId, list]] : kept);
  writeStored(RECENT_KEY, JSON.stringify(next));
  return next;
}

export const useSearchState = create<SearchState>((set) => ({
  keywords: [],
  options: DEFAULT_SEARCH_OPTIONS,
  popoverOpen: false,
  recent: readStoredJson(RECENT_KEY, isRecentSearches) ?? {},
  setKeywords: (keywords) => set({ keywords }),
  patchOptions: (patch) => set((s) => ({ options: { ...s.options, ...patch } })),
  resetOptions: () => set({ options: DEFAULT_SEARCH_OPTIONS }),
  setPopoverOpen: (popoverOpen) => set({ popoverOpen }),
  applySaved: (search) =>
    set((s) => ({
      keywords: Array.isArray(search.keywords) ? search.keywords.map(String) : [],
      options: {
        ...s.options,
        sources: Array.isArray(search.sources) ? search.sources.map(String) : s.options.sources,
        limit: typeof search.limit === "number" ? search.limit : s.options.limit,
      },
    })),
  rememberSearches: (runId, searches) =>
    set((s) => {
      const known = s.recent[runId] ?? [];
      const added = searches.filter((search) => !known.includes(search));
      if (added.length === 0) return s;
      const all = [...known, ...added];
      // Over the cap, the oldest chips outside this search make room.
      const spare = all.filter((search) => !searches.includes(search));
      const dropped = new Set(spare.slice(0, Math.max(0, all.length - MAX_RECENT_SEARCHES)));
      return {
        recent: withRun(
          s.recent,
          runId,
          all.filter((search) => !dropped.has(search)),
        ),
      };
    }),
  forgetSearch: (runId, search) =>
    set((s) => {
      const known = s.recent[runId] ?? [];
      if (!known.includes(search)) return s;
      return {
        recent: withRun(
          s.recent,
          runId,
          known.filter((item) => item !== search),
        ),
      };
    }),
}));
