/**
 * Public store hooks for every stream (S2 viewer, S3 grid, S4 tree/case).
 * These signatures are the S1 contract; prefer them over `useAppStore`.
 */

import { useCallback } from "react";
import { useShallow } from "zustand/react/shallow";
import type { CollectionId } from "../contracts/collection";
import type { ViewerMode, ViewerTarget } from "../contracts/viewer";
import type { ExplorerView, Route } from "../router";
import { type Density, effectiveTheme, type PanelLayout, type Theme } from "./slices/prefs";
import type { NavigateOptions, OpenCollectionOptions } from "./slices/route";
import { currentRun } from "./slices/runs";
import { type AppState, useAppStore } from "./store";

export interface RouteApi {
  route: Route;
  navigate: (route: Route, options?: NavigateOptions) => void;
  patchRoute: (patch: Partial<Route>, options?: NavigateOptions) => void;
  openCollection: (collection: CollectionId, options?: OpenCollectionOptions) => void;
  /** Explorer view from `view=` (S9); "columns" when absent. */
  view: ExplorerView;
}

/** Current route (from the hash) and navigation actions. */
export function useRoute(): RouteApi {
  return useAppStore(
    useShallow((s: AppState) => ({
      route: s.route,
      view: s.route.view ?? "columns",
      navigate: s.navigate,
      patchRoute: s.patchRoute,
      openCollection: s.openCollection,
    })),
  );
}

export interface SelectionApi {
  focusedRowKey: string | null;
  selectedRowKeys: string[];
  focusRow: (rowKey: string | null) => void;
  setSelectedRows: (rowKeys: string[]) => void;
  toggleRowSelected: (rowKey: string) => void;
  clearSelection: () => void;
}

/** Grid focus + multi-selection; cleared automatically when the collection changes. */
export function useSelection(): SelectionApi {
  return useAppStore(
    useShallow((s: AppState) => ({
      focusedRowKey: s.focusedRowKey,
      selectedRowKeys: s.selectedRowKeys,
      focusRow: s.focusRow,
      setSelectedRows: s.setSelectedRows,
      toggleRowSelected: s.toggleRowSelected,
      clearSelection: s.clearSelection,
    })),
  );
}

export interface ViewerTargetApi {
  target: ViewerTarget | null;
  setTarget: (target: ViewerTarget | null) => void;
  /** Mode from the URL (`mode=`), undefined = let the viewer auto-select. */
  mode: ViewerMode | undefined;
  setMode: (mode: ViewerMode | undefined) => void;
  /** True when the viewer is rendered as the < 1200 px overlay drawer. */
  isDrawer: boolean;
  drawerOpen: boolean;
}

/** The row the always-open viewer follows, mirrored into `row=` / `mode=`. */
export function useViewerTarget(): ViewerTargetApi {
  return useAppStore(
    useShallow((s: AppState) => ({
      target: s.viewerTarget,
      setTarget: s.setViewerTarget,
      mode: s.route.row ? s.route.mode : undefined,
      setMode: s.setViewerMode,
      isDrawer: s.viewerIsDrawer,
      drawerOpen: s.viewerDrawerOpen,
    })),
  );
}

export interface DensityApi {
  density: Density;
  /** Row height in px for virtualisers (24 / 28 / 32). */
  rowHeight: number;
  setDensity: (density: Density) => void;
  cycleDensity: () => void;
}

export const ROW_HEIGHT: Record<Density, number> = { compact: 24, default: 28, comfortable: 32 };

export function useDensity(): DensityApi {
  return useAppStore(
    useShallow((s: AppState) => ({
      density: s.density,
      rowHeight: ROW_HEIGHT[s.density],
      setDensity: s.setDensity,
      cycleDensity: s.cycleDensity,
    })),
  );
}

export interface ThemeApi {
  /** Explicit choice; null = following the OS. */
  theme: Theme | null;
  /** Theme actually shown. */
  effectiveTheme: Theme;
  setTheme: (theme: Theme | null) => void;
  toggleTheme: () => void;
}

export function useTheme(): ThemeApi {
  return useAppStore(
    useShallow((s: AppState) => ({
      theme: s.theme,
      effectiveTheme: effectiveTheme(s.theme),
      setTheme: s.setTheme,
      toggleTheme: s.toggleTheme,
    })),
  );
}

export function usePanelLayout(): [PanelLayout | null, (layout: PanelLayout | null) => void] {
  return useAppStore(useShallow((s: AppState) => [s.panelLayout, s.setPanelLayout] as const)) as [
    PanelLayout | null,
    (layout: PanelLayout | null) => void,
  ];
}

/** Runs from GET /api/runs (kept fresh by the status bar poller) and the routed run. */
export function useRuns() {
  return useAppStore(
    useShallow((s: AppState) => ({
      runs: s.runs,
      runsStatus: s.runsStatus,
      currentRun: currentRun(s),
    })),
  );
}

export interface TimezoneApi {
  /** Effective display timezone: URL `tz=` > user preference > evidence timezone > "local". */
  timezone: string;
  /** Explicit user/URL choice; null = following the default. */
  choice: string | null;
  setTimezone: (timezone: string | null) => void;
}

/** Evidence timezone carried by the run record (`evidence_timezone` / `timezone`), if any. */
export function runEvidenceTimezone(run: unknown): string | null {
  if (!run || typeof run !== "object") return null;
  const record = run as Record<string, unknown>;
  const request = (record.request ?? {}) as Record<string, unknown>;
  for (const value of [
    record.evidence_timezone,
    record.timezone,
    request.evidence_timezone,
    request.timezone,
  ]) {
    if (typeof value === "string" && value) return value;
  }
  return null;
}

/** Global display timezone for every time column / viewer field (X4). */
export function useTimezone(): TimezoneApi {
  const choice = useAppStore((s) => s.route.tz ?? s.timezone);
  const evidence = useAppStore((s) => runEvidenceTimezone(currentRun(s)));
  const setTimezone = useCallback((tz: string | null) => {
    const s = useAppStore.getState();
    s.setTimezone(tz);
    if (s.route.runId) s.patchRoute({ tz: tz ?? undefined }, { replace: true });
  }, []);
  return { timezone: choice ?? evidence ?? "local", choice, setTimezone };
}
