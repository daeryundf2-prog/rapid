import { create } from "zustand";

type SearchBackend = "index" | "scan";

/**
 * What the search grid's first page is doing, for the status line above the grid. The page
 * fetcher writes it (`rows.ts`); later pages load silently like any other grid page.
 */
interface SearchActivity {
  /** A first page is on its way from this backend. */
  pending: SearchBackend | null;
  /** Backend of the last first page that arrived, with the server's notes on it. */
  arrived: { backend: SearchBackend; warnings: readonly string[] } | null;
  /** Why the search runs as a scan although the run may have an index (an option only the scan has). */
  scanReason: string | null;
  /** The analyst stopped the pending search. */
  cancelled: boolean;
  begin: (backend: SearchBackend, scanReason: string | null) => void;
  arrive: (backend: SearchBackend, warnings: readonly string[]) => void;
  /** The pending first page ended without rows (error, abort). */
  settle: () => void;
  cancel: () => void;
}

export const useSearchActivity = create<SearchActivity>((set) => ({
  pending: null,
  arrived: null,
  scanReason: null,
  cancelled: false,
  begin: (backend, scanReason) => set({ pending: backend, scanReason, cancelled: false }),
  arrive: (backend, warnings) => set({ pending: null, arrived: { backend, warnings } }),
  settle: () => set({ pending: null }),
  cancel: () => set({ pending: null, cancelled: true }),
}));
