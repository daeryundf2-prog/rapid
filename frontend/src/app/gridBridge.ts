/**
 * Shell ⇄ grid wiring (S1 ⇄ S3).
 *
 * The grid keeps its own small store behind features/grid/adapter.ts (its
 * tests drive that store directly). In the app this bridge makes the shell
 * the source of truth: route / density / search options flow into the grid
 * store; the grid's filter, navigation, selection, published viewer target
 * and "open viewer" requests flow back into the app store. Every write is
 * guarded by an equality check, so the two subscriptions cannot loop.
 */

import { expandViewerPane, focusViewer, MAIN_ID } from "../commands/builtin";
import type { CollectionQuery, CollectionRef } from "../contracts/collection";
import { encodeRowRef, type RowRef } from "../contracts/rowRef";
import type { ViewerTarget } from "../contracts/viewer";
import { useSearchState } from "../features/case/searchState";
import { type RouteState, useGridLocalStore } from "../features/grid/adapter";
import { collectionChanged, stageHasViewer, stageOf } from "../router";
import { useAppStore } from "../state/store";

function rowKey(ref: RowRef | null | undefined): string {
  return ref ? encodeRowRef(ref) : "";
}

function targetKey(target: ViewerTarget | null): string {
  return target
    ? `${target.runId}|${rowKey(target.ref)}|${target.sourcePath ?? ""}|${target.preferredMode ?? ""}`
    : "";
}

function sameCollection(a: CollectionRef, b: CollectionRef): boolean {
  return (
    a.id === b.id &&
    (a.kind ?? "") === (b.kind ?? "") &&
    (a.status ?? "") === (b.status ?? "") &&
    (a.category ?? "") === (b.category ?? "") &&
    (a.analysisId ?? "") === (b.analysisId ?? "") &&
    a.dir === b.dir &&
    Boolean(a.recursive) === Boolean(b.recursive) &&
    (a.special ?? "") === (b.special ?? "")
  );
}

/** Search spec for the grid from the routed keywords + S4's options popover. */
export function searchSpec(q: string | undefined): CollectionQuery["search"] {
  const keywords = (q ?? "").split(/[\s,]+/).filter(Boolean);
  if (keywords.length === 0) return undefined;
  const { options } = useSearchState.getState();
  return {
    keywords,
    mode: options.mode,
    sources: options.sources.length ? options.sources : undefined,
    hideKnownGood: options.hideKnownGood,
  };
}

/** The grid route the shell route implies. */
export function gridRouteFromShell(): RouteState {
  const { route } = useAppStore.getState();
  const collection: CollectionRef = { id: route.collection ?? "intake" };
  if (route.kind) collection.kind = route.kind;
  if (route.status) collection.status = route.status;
  if (route.category) collection.category = route.category;
  if (route.collection === "analysis" && route.analysisId) collection.analysisId = route.analysisId;
  if (route.collection === "files" && route.dir !== undefined) {
    collection.dir = route.dir;
    if (route.rec) collection.recursive = true;
  }
  if (route.collection === "files" && route.special) collection.special = route.special;
  const isSearch = collection.id === "search";
  const grid = useGridLocalStore.getState().route;
  return {
    runId: route.runId,
    collection,
    // On the search node `q` is the FTS query; the grid filter stays local there.
    q: isSearch ? (sameCollection(grid.collection, collection) ? grid.q : "") : (route.q ?? ""),
    search: isSearch ? searchSpec(route.q) : undefined,
    rowRef: route.row ?? null,
    sort: route.sort,
    cols: route.cols,
  };
}

function gridRouteEqual(a: RouteState, b: RouteState): boolean {
  return (
    a.runId === b.runId &&
    sameCollection(a.collection, b.collection) &&
    a.q === b.q &&
    JSON.stringify(a.search ?? null) === JSON.stringify(b.search ?? null) &&
    rowKey(a.rowRef) === rowKey(b.rowRef) &&
    JSON.stringify(a.sort ?? null) === JSON.stringify(b.sort ?? null) &&
    JSON.stringify(a.cols ?? null) === JSON.stringify(b.cols ?? null)
  );
}

function pushShellToGrid(): void {
  const grid = useGridLocalStore.getState();
  const next = gridRouteFromShell();
  if (!gridRouteEqual(grid.route, next)) grid.setRoute(next);
  const { density } = useAppStore.getState();
  if (grid.density !== density) grid.setDensity(density);
}

let userTouchedGrid = false;

/** Install the bridge; returns the disconnect function. */
export function connectGridToShell(): () => void {
  pushShellToGrid();

  // Has the analyst moved/selected in the grid since this collection opened?
  const markTouched = (event: Event) => {
    if (event.target instanceof Element && event.target.closest(`#${MAIN_ID}`)) userTouchedGrid = true;
  };
  document.addEventListener("keydown", markTouched, true);
  document.addEventListener("pointerdown", markTouched, true);

  const offApp = useAppStore.subscribe((state, prev) => {
    // A new collection, server order or filter re-resolves the focused row from `row=`:
    // until the analyst moves again, automatic focus must not rewrite the URL row.
    if (
      collectionChanged(prev.route, state.route) ||
      JSON.stringify(prev.route.sort ?? null) !== JSON.stringify(state.route.sort ?? null) ||
      (prev.route.q ?? "") !== (state.route.q ?? "") ||
      (prev.route.path ?? "") !== (state.route.path ?? "")
    ) {
      userTouchedGrid = false;
    }
    if (state.route !== prev.route || state.density !== prev.density) pushShellToGrid();
  });
  const offSearch = useSearchState.subscribe((state, prev) => {
    if (state.options !== prev.options) pushShellToGrid();
  });

  const offGrid = useGridLocalStore.subscribe((grid, prev) => {
    const app = useAppStore.getState();

    // Grid navigation ("타임라인에서 보기", "같은 출처 행") or filter typing.
    if (!sameCollection(grid.route.collection, prev.route.collection)) {
      const ref = grid.route.collection;
      if (
        ref.id === "review" &&
        prev.route.collection.id === "review" &&
        app.route.collection === "review" &&
        ref.status !== app.route.status
      ) {
        // 검토 toolbar 리뷰 상태: a patch of the same page, so tags / time / types / ext / path
        // filters stay (openCollection would start a clean route — review B2-5).
        app.patchRoute({ status: ref.status, row: undefined });
      } else if (!sameCollection(ref, gridRouteFromShell().collection)) {
        app.openCollection(ref.id, {
          kind: ref.kind,
          status: ref.status,
          category: ref.category,
          q: grid.route.q || undefined,
        });
      }
    } else {
      if (grid.route.q !== prev.route.q && grid.route.collection.id !== "search") {
        if ((app.route.q ?? "") !== grid.route.q) {
          app.patchRoute({ q: grid.route.q || undefined }, { replace: true });
        }
      }
      // Server sort / promoted field columns (artifacts of one kind) ride in the URL.
      if (grid.route.sort !== prev.route.sort || grid.route.cols !== prev.route.cols) {
        const sort = grid.route.sort;
        const cols = grid.route.cols?.length ? grid.route.cols : undefined;
        if (
          JSON.stringify(sort ?? null) !== JSON.stringify(useAppStore.getState().route.sort ?? null) ||
          JSON.stringify(cols ?? null) !== JSON.stringify(useAppStore.getState().route.cols ?? null)
        ) {
          useAppStore.getState().patchRoute({ sort, cols }, { replace: true });
        }
      }
    }

    // Focused row → viewer (with the full GridRow for the viewer's 레코드 section and the
    // review keys). Automatic focus (first row on open) loads the viewer without writing `row=`.
    if ((grid.target !== prev.target || grid.focusedRow !== prev.focusedRow) && grid.target) {
      const row = grid.focusedRow ?? null;
      const pendingDeepLink =
        !userTouchedGrid &&
        app.route.row !== undefined &&
        app.route.row.collection === app.route.collection &&
        rowKey(app.route.row) !== rowKey(grid.target.ref);
      if (pendingDeepLink) {
        // Auto-focus of row 0 before the grid restores the `row=` deep link: ignore it.
      } else if (targetKey(grid.target) !== targetKey(app.viewerTarget)) {
        app.setViewerTarget(grid.target, { row, syncUrl: userTouchedGrid });
      } else if (userTouchedGrid && rowKey(app.route.row) !== rowKey(grid.target.ref)) {
        // A click / key on the row the viewer already shows (the auto-focused first row) is the
        // analyst's choice: mirror it into `row=` now.
        app.setViewerTarget(app.viewerTarget, { row: row ?? app.viewerRow, syncUrl: true });
      } else if (row && row !== app.viewerRow) {
        app.setViewerTarget(app.viewerTarget, { row, syncUrl: false });
      }
    }
    if (grid.selectedKeys !== prev.selectedKeys) {
      const keys = [...grid.selectedKeys];
      const current = useAppStore.getState().selectedRowKeys;
      if (keys.length !== current.length || keys.some((k, i) => k !== current[i])) app.setSelectedRows(keys);
    }
    if (grid.focusedRowKey !== prev.focusedRowKey && grid.focusedRowKey !== app.focusedRowKey) {
      app.focusRow(grid.focusedRowKey);
    }
    if (grid.density !== prev.density && grid.density !== app.density) app.setDensity(grid.density);

    // Enter on a row: open (drawer) + focus the viewer.
    // Never on a stage without a mounted viewer (접수·처리·보고): the drawer overlay would
    // otherwise pop open later, when the user returns to 탐색.
    if (grid.viewerFocusRequests > prev.viewerFocusRequests && stageHasViewer(stageOf(app.route))) {
      const s = useAppStore.getState();
      if (s.viewerIsDrawer) s.setOverlay("viewerDrawer", true);
      else expandViewerPane();
      focusViewer();
    }
  });

  return () => {
    document.removeEventListener("keydown", markTouched, true);
    document.removeEventListener("pointerdown", markTouched, true);
    offApp();
    offSearch();
    offGrid();
  };
}
