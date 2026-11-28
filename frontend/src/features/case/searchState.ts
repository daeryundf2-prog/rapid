import { create } from "zustand";
import type { SavedSearch } from "../../api/caseDb";
import { DEFAULT_SEARCH_OPTIONS, type SearchOptions } from "../../api/keywordPacks";
import { type QuestionPack, searchFromQuestion } from "../../api/questionPacks";

/**
 * Search options + the keywords the top-bar search (S1) is about to run.
 * The options popover writes here; S1's search input reads `options` when it
 * builds the request with `searchPath()` / `searchQueryString()`.
 */
interface SearchState {
  keywords: string[];
  options: SearchOptions;
  popoverOpen: boolean;
  setKeywords: (keywords: string[]) => void;
  patchOptions: (patch: Partial<SearchOptions>) => void;
  resetOptions: () => void;
  setPopoverOpen: (open: boolean) => void;
  /** Load a saved search into the state (keywords + sources + limit). */
  applySaved: (search: SavedSearch) => void;
  /** 질문 팩 하나를 검색으로 옮긴다(검색어 + 범위·확장자·키워드 팩). */
  applyQuestion: (pack: QuestionPack) => void;
}

export const useSearchState = create<SearchState>((set) => ({
  keywords: [],
  options: DEFAULT_SEARCH_OPTIONS,
  popoverOpen: false,
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
  applyQuestion: (pack) =>
    set((s) => {
      const search = searchFromQuestion(pack);
      return { keywords: search.keywords, options: { ...s.options, ...search.options } };
    }),
}));
