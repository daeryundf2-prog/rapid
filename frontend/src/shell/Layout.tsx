import { type RefObject, useCallback, useEffect, useRef, useState } from "react";
import {
  Group,
  type GroupImperativeHandle,
  Panel,
  type PanelImperativeHandle,
  Separator,
} from "react-resizable-panels";
import { SkipLink, useEscape } from "../a11y";
import { COLLECTION_LABEL } from "../app/collections";
import {
  closeTreeDrawer,
  expandViewerPane,
  focusMain,
  focusViewer,
  MAIN_ID,
  TREE_COLLAPSE_ID,
  TREE_DRAWER_ID,
  TREE_EXPAND_ID,
  VIEWER_EXPAND_ID,
  VIEWER_ID,
} from "../commands/builtin";
import { CommandButton } from "../commands/CommandButton";
import { runCommand, useCommandState } from "../commands/registry";
import { ToastRegion } from "../components/ToastRegion";
import { KEY_MAP } from "../contracts/command";
import { ActionsHost } from "../features/actions/ActionsHost";
import { Landing } from "../features/case/Landing";
import { ReviewToolsHost } from "../features/review/ReviewToolsHost";
import { readClassicLayout, useViewPrefs, writeClassicLayout } from "../features/review/viewPrefs";
import { StageRail } from "../features/stages/StageRail";
import { STAGE_DEFS, STAGE_HEADING_ID } from "../features/stages/stages";
import { useTreePrefs } from "../features/tree/treePrefs";
import { focusPopout, returnViewerFromPopout, usePopoutHost } from "../features/viewer/popout/host";
import { Icon } from "../icons";
import { stageHasViewer, stageOf } from "../router";
import { keyLabel } from "../shortcuts";
import { usePanelLayout } from "../state/hooks";
import { viewerPaneCollapsed } from "../state/slices/overlays";
import { treePanelHidden } from "../state/slices/prefs";
import { useAppStore } from "../state/store";
import { CommandPalette } from "./CommandPalette";
import { HelpOverlay } from "./HelpOverlay";
import { StatusBar } from "./StatusBar";
import { Slot } from "./slots";
import { TopBar } from "./TopBar";

/** Below this width the viewer becomes an overlay drawer (plan §4.1). */
export const DRAWER_QUERY = "(max-width: 1199.98px)";
/**
 * Below this width the stage's left panel (tree) becomes a drawer too: beside a 240px tree the
 * grid kept two columns at 720px and one at 500px (the desktop window's minimum).
 */
export const TREE_DRAWER_QUERY = "(max-width: 899.98px)";
/**
 * Phones (F23, review X8): the viewer drawer is a full-width detail screen with 목록으로, and
 * tapping a row opens it (list ↔ detail).
 */
export const PHONE_QUERY = "(max-width: 599.98px)";
/** Panel ids are DOM ids too: keep them distinct from the landmark ids (#main, #viewer). */
const PANEL = { tree: "pane-tree", grid: "pane-grid", viewer: "pane-viewer" } as const;
/**
 * Default pane widths (visual-polish B2 #2): the tree and the viewer have fixed pixel widths, the
 * grid takes the rest. On 탐색·검토 the viewer is a 36px rail until a row is selected, so at
 * 1440px the grid gets ≈ 1076px (≈ 672px beside the open viewer; the grid then hides its
 * lowest-priority default columns). Every pane stays resizable; a dragged layout is saved
 * (percentages) and restored when the viewer expands.
 */
export const TREE_DEFAULT = "260px";
export const VIEWER_DEFAULT = "440px";
/** Width of the collapsed viewer rail (no row selected, or 뷰어 접기). */
export const VIEWER_RAIL = "36px";
/** Width of the folded stage panel strip (F24). */
export const TREE_RAIL = "36px";

export function useMediaQuery(query: string): boolean {
  const get = () =>
    typeof window !== "undefined" && window.matchMedia ? window.matchMedia(query).matches : false;
  const [matches, setMatches] = useState(get);
  useEffect(() => {
    if (!window.matchMedia) return;
    const list = window.matchMedia(query);
    const onChange = () => setMatches(list.matches);
    onChange();
    list.addEventListener?.("change", onChange);
    return () => list.removeEventListener?.("change", onChange);
  }, [query]);
  return matches;
}

/** 접기 at the panel's heading (wide layout, F24): folds the panel to its strip, Alt+0. */
function TreeFoldButton() {
  const panel = useAppStore((s) => STAGE_DEFS[stageOf(s.route)].panelLabel);
  const { run } = useCommandState("tree.panel");
  return (
    <button
      type="button"
      id={TREE_COLLAPSE_ID}
      className="button ghost icon-only tree-fold-button"
      aria-label={`${panel} 접기`}
      aria-expanded={true}
      aria-keyshortcuts={KEY_MAP.treePanel}
      title={`${panel} 접기 (${keyLabel(KEY_MAP.treePanel)})`}
      data-testid="tree-collapse"
      onClick={() => void run()}
    >
      <Icon name="panel-left-close" />
    </button>
  );
}

function TreePane({ foldable = false, hidden = false }: { foldable?: boolean; hidden?: boolean }) {
  // The left panel follows the stage (console-ia §3): domain tree, runs, review lists, exports.
  const label = useAppStore((s) => STAGE_DEFS[stageOf(s.route)].panelLabel);
  const stage = useAppStore((s) => (s.route.runId ? STAGE_DEFS[stageOf(s.route)].label : ""));
  return (
    <nav className="pane-frame" aria-label={label} data-testid="tree-region" hidden={hidden}>
      <div className="stage-heading-row">
        {/* Stage switches (rail / Alt+1..5) land focus here (console-ia §3, Q-IA-1). */}
        <h1 id={STAGE_HEADING_ID} tabIndex={-1} className="stage-heading">
          {stage || "케이스"}
        </h1>
        {foldable ? <TreeFoldButton /> : null}
      </div>
      {/* The panel body scrolls (the frame clipped a long tree at 768px: 결과 없는 계열 vanished). */}
      <div className="pane-scroll">
        <Slot name="tree" fallback={<p className="pane-empty">탐색 트리를 불러오는 중…</p>} />
      </div>
    </nav>
  );
}

/**
 * The folded stage panel (F24, review X2): a 36px strip naming where the analyst is (the tree's
 * selected node, else the view) — the whole strip is the 펼치기 button (Alt+0).
 */
function TreeStrip() {
  const panel = useAppStore((s) => STAGE_DEFS[stageOf(s.route)].panelLabel);
  const treeLocation = useTreePrefs((s) => s.location);
  const collection = useAppStore((s) => s.route.collection);
  const location = treeLocation || (collection ? COLLECTION_LABEL[collection] : "");
  const { run } = useCommandState("tree.panel");
  return (
    <div className="tree-strip" data-testid="tree-strip">
      <button
        type="button"
        id={TREE_EXPAND_ID}
        className="tree-strip-button"
        aria-label={`${panel} 펼치기`}
        aria-description={location ? `현재 위치: ${location}` : undefined}
        aria-expanded={false}
        aria-keyshortcuts={KEY_MAP.treePanel}
        title={`${panel} 펼치기 (${keyLabel(KEY_MAP.treePanel)})${location ? ` — ${location}` : ""}`}
        onClick={() => void run()}
      >
        <Icon name="panel-left-open" />
        {location ? (
          <span className="tree-strip-text" aria-hidden="true">
            {location}
          </span>
        ) : null}
      </button>
    </div>
  );
}

interface TreeFold {
  ref: RefObject<PanelImperativeHandle | null>;
  /** The current collection kind is folded to the strip. */
  hidden: boolean;
  initiallyHidden: boolean;
  /** Re-apply the fold (after a saved layout is restored). */
  sync: () => void;
  /** A user drag across the collapse threshold pins the fold like the buttons. */
  onUserLayout: () => void;
}

/**
 * Wide layout tree fold (F24): the tree Panel collapses to the strip while the current collection
 * kind is folded (timeline · search · review start folded, pinned per kind).
 */
function useTreeFold(size: string): TreeFold {
  const ref = useRef<PanelImperativeHandle>(null);
  const hidden = useAppStore(treePanelHidden);
  const hiddenRef = useRef(hidden);
  hiddenRef.current = hidden;
  const [initiallyHidden] = useState(hidden);
  const sync = useCallback(() => {
    const panel = ref.current;
    if (!panel) return;
    if (hiddenRef.current) {
      if (!panel.isCollapsed()) panel.collapse();
    } else if (panel.isCollapsed()) panel.resize(size);
  }, [size]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: re-sync whenever the fold changes
  useEffect(() => sync(), [hidden, sync]);
  const onUserLayout = useCallback(() => {
    const shut = ref.current?.isCollapsed() ?? false;
    if (shut !== hiddenRef.current) useAppStore.getState().setTreePanelHidden(shut);
  }, []);
  return { ref, hidden, initiallyHidden, sync, onUserLayout };
}

function TreeColumn({ fold, size }: { fold: TreeFold; size: string }) {
  return (
    <Panel
      id={PANEL.tree}
      panelRef={fold.ref}
      defaultSize={fold.initiallyHidden ? TREE_RAIL : size}
      minSize="240px"
      maxSize="320px"
      collapsible
      collapsedSize={TREE_RAIL}
    >
      {fold.hidden ? <TreeStrip /> : null}
      {/* Kept mounted while folded: the tree keeps its open nodes, its search and its location. */}
      <TreePane foldable hidden={fold.hidden} />
    </Panel>
  );
}

function GridPane() {
  return (
    <main id={MAIN_ID} tabIndex={-1} className="pane-frame" aria-label="목록" data-testid="grid-region">
      <Slot name="grid" fallback={<p className="pane-empty">목록을 불러오는 중…</p>} />
    </main>
  );
}

function ViewerSlot({ drawer }: { drawer: boolean }) {
  return <Slot name="viewer" drawer={drawer} fallback={<p className="pane-empty">선택된 행이 없습니다</p>} />;
}

export { stageHasViewer, VIEWER_STAGES } from "../router";

/**
 * Narrow layout (< 900px): the stage's left panel as a drawer over the page, opened by the stage
 * rail's toggle (Alt+0, tree.panel). Esc, the scrim and the toggle close it and return focus to
 * the toggle; a destination picked in it closes it too and focus follows to the page. It stays
 * mounted while closed, so the tree keeps its expanded nodes and its search.
 */
function TreeDrawer() {
  const open = useAppStore((s) => s.treeDrawerOpen);
  const ref = useRef<HTMLDivElement>(null);
  useEscape(closeTreeDrawer, open);
  useEffect(() => {
    if (!open) return;
    return useAppStore.subscribe((state, prev) => {
      // A stage switch only changes which panel the drawer shows.
      if (state.route === prev.route || stageOf(state.route) !== stageOf(prev.route)) return;
      if (!ref.current?.contains(document.activeElement)) return;
      state.setOverlay("treeDrawer", false);
      focusMain();
    });
  }, [open]);
  return (
    <>
      {open ? (
        <button
          type="button"
          className="drawer-scrim"
          aria-label="패널 닫기"
          tabIndex={-1}
          onClick={closeTreeDrawer}
        />
      ) : null}
      <div ref={ref} id={TREE_DRAWER_ID} className="tree-drawer" data-testid="tree-drawer" hidden={!open}>
        <TreePane />
      </div>
    </>
  );
}

/** The stage's left panel and the page: side by side, or (`drawer`) the page alone under the panel drawer. */
function TreeAndGrid({ id, treeSize, drawer }: { id: string; treeSize: string; drawer: boolean }) {
  if (drawer) {
    return (
      <>
        <TreeDrawer />
        <GridPane />
      </>
    );
  }
  return <InlineTreeAndGrid id={id} treeSize={treeSize} />;
}

function InlineTreeAndGrid({ id, treeSize }: { id: string; treeSize: string }) {
  const fold = useTreeFold(treeSize);
  return (
    <Group
      id={id}
      orientation="horizontal"
      onLayoutChanged={(_layout, meta) => {
        if (meta?.isUserInteraction) fold.onUserLayout();
      }}
      style={{ height: "100%" }}
    >
      <TreeColumn fold={fold} size={treeSize} />
      <Separator className="resize-handle" />
      <Panel id={PANEL.grid} minSize="320px">
        <GridPane />
      </Panel>
    </Group>
  );
}

/** 접수·처리·보고: left panel + page, no viewer column. */
function TwoPanes({ narrow, treeDrawer }: { narrow: boolean; treeDrawer: boolean }) {
  return (
    <TreeAndGrid id="rapidtriage-console-2col" treeSize={narrow ? "28%" : TREE_DEFAULT} drawer={treeDrawer} />
  );
}

/** No case open (visual-polish S10): the landing card is the page's main content. */
function LandingPane() {
  return (
    <main id={MAIN_ID} tabIndex={-1} className="pane-frame landing-frame" aria-label="시작">
      <Landing />
    </main>
  );
}

/**
 * The collapsed viewer (review #19): an icon-only rail (panel-right-open) with a tooltip; a dot
 * on the icon says a row is selected and waiting in the viewer.
 */
function ViewerRail() {
  const hasRow = useAppStore((s) => Boolean(s.route.row));
  const label = hasRow ? "뷰어 펼치기 (선택한 행 있음)" : "뷰어 펼치기";
  return (
    <div className="viewer-rail" data-testid="viewer-rail">
      <button
        type="button"
        id={VIEWER_EXPAND_ID}
        className="viewer-rail-button"
        aria-label="뷰어 펼치기"
        aria-description={hasRow ? "선택한 행이 있습니다" : undefined}
        aria-expanded={false}
        title={label}
        data-has-row={hasRow ? "" : undefined}
        onClick={() => {
          expandViewerPane();
          // Focus follows into the viewer once it renders (the rail button goes away).
          focusViewer();
        }}
      >
        <span className="viewer-rail-icon">
          <Icon name="panel-right-open" />
          {hasRow ? <span className="viewer-rail-dot" aria-hidden="true" /> : null}
        </span>
      </button>
    </div>
  );
}

/**
 * The viewer lives in its own window (U-F2): the pane is a rail that says so, with 되돌리기 and a
 * button that brings the viewer window forward.
 */
function PopoutRail() {
  return (
    <div className="viewer-rail viewer-rail-popout" data-testid="viewer-popout-rail">
      <button
        type="button"
        className="viewer-rail-button"
        aria-label="뷰어 창 앞으로 가져오기"
        title="뷰어 창 앞으로 가져오기"
        onClick={() => focusPopout()}
      >
        <span className="viewer-rail-icon">
          <Icon name="external" />
        </span>
      </button>
      <p className="viewer-rail-text">창으로 보는 중</p>
      <button
        type="button"
        className="viewer-rail-button"
        aria-label="창으로 보는 중 · 되돌리기 (뷰어 창을 닫고 이 열에 다시 표시)"
        title="되돌리기 — 뷰어 창을 닫고 이 열에 다시 표시"
        data-testid="viewer-popout-return"
        onClick={() => {
          returnViewerFromPopout();
          focusViewer();
        }}
      >
        <span className="viewer-rail-icon">
          <Icon name="panel-right-open" />
        </span>
      </button>
    </div>
  );
}

function validLayout(layout: Record<string, number> | null): layout is Record<string, number> {
  return Boolean(layout?.[PANEL.tree] && layout[PANEL.grid] && layout[PANEL.viewer]);
}

function WidePanes() {
  const [saved, setSaved] = usePanelLayout();
  const groupRef = useRef<GroupImperativeHandle>(null);
  const viewerRef = useRef<PanelImperativeHandle>(null);
  const poppedOut = usePopoutHost((s) => s.status === "open");
  const paneCollapsed = useAppStore(viewerPaneCollapsed);
  const collapsed = paneCollapsed || poppedOut;
  const collapsedRef = useRef(collapsed);
  collapsedRef.current = collapsed;
  const savedRef = useRef(saved);
  savedRef.current = saved;
  const [initiallyCollapsed] = useState(collapsed);
  // An explicit expand without a row ("open") falls back to "auto" once a row is selected, so
  // leaving the row (another collection) collapses the pane again.
  const hasRow = useAppStore((s) => Boolean(s.route.row));
  const pane = useAppStore((s) => s.viewerPane);
  const setViewerPane = useAppStore((s) => s.setViewerPane);
  useEffect(() => {
    if (pane === "open" && hasRow) setViewerPane("auto");
  }, [pane, hasRow, setViewerPane]);
  const fold = useTreeFold(TREE_DEFAULT);
  // The library reads `defaultLayout` before panels register; apply a saved (dragged) layout
  // imperatively once after mount. Without one the panels' pixel defaults apply. The tree fold
  // (F24) is re-applied over a restored layout.
  // biome-ignore lint/correctness/useExhaustiveDependencies: mount-only initialisation
  useEffect(() => {
    if (validLayout(saved) && !initiallyCollapsed) {
      groupRef.current?.setLayout(saved);
      fold.sync();
    }
  }, []);
  // Collapse to the rail / expand back to the saved (dragged) width, else the 440px default.
  // biome-ignore lint/correctness/useExhaustiveDependencies: fold.sync is stable for the pane's size
  useEffect(() => {
    const panel = viewerRef.current;
    if (!panel) return;
    if (collapsed) {
      if (!panel.isCollapsed()) panel.collapse();
      return;
    }
    if (!panel.isCollapsed()) return;
    const layout = savedRef.current;
    if (validLayout(layout)) {
      groupRef.current?.setLayout(layout);
      fold.sync();
    }
    if (panel.isCollapsed()) panel.resize(VIEWER_DEFAULT);
  }, [collapsed]);
  return (
    <Group
      id="rapidtriage-console"
      orientation="horizontal"
      groupRef={groupRef}
      onLayoutChanged={(layout, meta) => {
        if (!meta?.isUserInteraction) return;
        fold.onUserLayout();
        const draggedShut = viewerRef.current?.isCollapsed() ?? false;
        // A drag across the collapse threshold is the same choice as the buttons.
        if (draggedShut !== collapsedRef.current) setViewerPane(draggedShut ? "collapsed" : "open");
        // Only an expanded viewer's width is worth restoring.
        if (!draggedShut) setSaved({ ...layout });
      }}
      style={{ height: "100%" }}
    >
      <TreeColumn fold={fold} size={TREE_DEFAULT} />
      <Separator className="resize-handle" />
      <Panel id={PANEL.grid} minSize="320px">
        <GridPane />
      </Panel>
      <Separator className="resize-handle" />
      <Panel
        id={PANEL.viewer}
        panelRef={viewerRef}
        defaultSize={initiallyCollapsed ? VIEWER_RAIL : VIEWER_DEFAULT}
        minSize="420px"
        collapsible
        collapsedSize={VIEWER_RAIL}
      >
        <aside
          id={VIEWER_ID}
          tabIndex={-1}
          className="pane-frame"
          aria-label="뷰어 패널"
          data-testid="viewer-region"
          data-collapsed={collapsed ? "" : undefined}
        >
          {poppedOut ? <PopoutRail /> : collapsed ? <ViewerRail /> : null}
          {/* The viewer stays mounted while collapsed: its history (Alt+←/→) and commands live on.
              While it lives in its own window (U-F2) it is unmounted here: one viewer fetches
              previews and hashes, not two. */}
          {poppedOut ? null : (
            <div className="viewer-slot" hidden={collapsed}>
              <ViewerSlot drawer={false} />
            </div>
          )}
        </aside>
      </Panel>
    </Group>
  );
}

/**
 * Phones (F23): a tap on a grid row's text opens the detail (the drawer, full width) — the
 * checkbox, the row menu and in-cell links stay in the list. Enter already opens it (gridBridge).
 */
function useRowTapOpensViewer(enabled: boolean): void {
  useEffect(() => {
    if (!enabled) return;
    const onClick = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      if (!target?.closest(`#${MAIN_ID} [role="row"][data-index]`)) return;
      if (target.closest('input, button, a[href], label, select, textarea, [role="checkbox"]')) return;
      if (target.closest(".grid-cell-select")) return;
      void runCommand("viewer.open");
    };
    document.addEventListener("click", onClick);
    return () => document.removeEventListener("click", onClick);
  }, [enabled]);
}

/**
 * The 뷰어 열기 bar under the list (drawer layout), only while there is a row to open. Its own
 * component: subscribing the panes to the command registry re-rendered the grid on every
 * (un)registration, and the grid's own registrations looped.
 */
function DrawerHandle() {
  if (useCommandState("viewer.open").disabledReason) return null;
  return (
    // A bar under the list, not a floating button over the rows' text (before-03-390).
    <div className="drawer-handle">
      <CommandButton command="viewer.open" label="뷰어 열기" testId="viewer-drawer-open" />
    </div>
  );
}

function NarrowPanes({ treeDrawer }: { treeDrawer: boolean }) {
  const open = useAppStore((s) => s.viewerDrawerOpen);
  const setOverlay = useAppStore((s) => s.setOverlay);
  const phone = useMediaQuery(PHONE_QUERY);
  useRowTapOpensViewer(phone);
  // Back to the list: focus returns to the grid's roving row, the row the detail showed.
  const close = () => {
    setOverlay("viewerDrawer", false);
    focusMain();
  };
  useEscape(close, open);
  return (
    <div className="narrow-panes" data-phone={phone ? "" : undefined}>
      <div className="narrow-panes-main">
        <TreeAndGrid id="rapidtriage-console-narrow" treeSize="28%" drawer={treeDrawer} />
      </div>
      {open ? (
        <button type="button" className="drawer-scrim" aria-label="뷰어 닫기" tabIndex={-1} onClick={close} />
      ) : (
        <DrawerHandle />
      )}
      <aside
        id={VIEWER_ID}
        tabIndex={-1}
        className={`viewer-drawer${open ? " open" : ""}`}
        aria-label="뷰어 패널"
        data-testid="viewer-region"
        hidden={!open}
      >
        <div className="drawer-head">
          {phone ? (
            <button
              type="button"
              className="button ghost drawer-back"
              data-testid="viewer-drawer-back"
              aria-label="목록으로 돌아가기 (Esc)"
              onClick={close}
            >
              <Icon name="arrow-left" />
              <span>목록으로</span>
            </button>
          ) : (
            <button
              type="button"
              className="button ghost icon-only"
              aria-label="뷰어 닫기 (Esc)"
              onClick={close}
            >
              <Icon name="close" />
            </button>
          )}
        </div>
        <ViewerSlot drawer />
      </aside>
    </div>
  );
}

/**
 * 클래식 분할 (AXIOM E3, research §7.2): tree | grid above · viewer (details) below, both
 * resizable. Toggled by ` (view.classicSplit) and kept across reloads. The viewer is always
 * shown here (no rail); while it lives in its own window the bottom pane says so.
 */
function ClassicPanes() {
  const poppedOut = usePopoutHost((s) => s.status === "open");
  const rowsRef = useRef<GroupImperativeHandle>(null);
  // Like WidePanes: a dragged grid/viewer split is saved and applied once after mount.
  useEffect(() => {
    const saved = readClassicLayout();
    if (saved?.[PANEL.grid] && saved[PANEL.viewer]) rowsRef.current?.setLayout(saved);
  }, []);
  const fold = useTreeFold(TREE_DEFAULT);
  return (
    <Group
      id="rapidtriage-console-classic"
      orientation="horizontal"
      onLayoutChanged={(_layout, meta) => {
        if (meta?.isUserInteraction) fold.onUserLayout();
      }}
      style={{ height: "100%" }}
    >
      <TreeColumn fold={fold} size={TREE_DEFAULT} />
      <Separator className="resize-handle" />
      <Panel id="pane-classic" minSize="420px">
        <Group
          id="rapidtriage-console-classic-rows"
          orientation="vertical"
          groupRef={rowsRef}
          onLayoutChanged={(layout, meta) => {
            if (meta?.isUserInteraction) writeClassicLayout({ ...layout });
          }}
          style={{ height: "100%" }}
        >
          <Panel id={PANEL.grid} defaultSize="55%" minSize="160px">
            <GridPane />
          </Panel>
          <Separator className="resize-handle resize-handle-rows" />
          <Panel id={PANEL.viewer} defaultSize="45%" minSize="160px">
            <aside
              id={VIEWER_ID}
              tabIndex={-1}
              className="pane-frame"
              aria-label="뷰어 패널 (아래)"
              data-testid="viewer-region"
              data-split="classic"
            >
              {poppedOut ? (
                <PopoutRail />
              ) : (
                <div className="viewer-slot">
                  <ViewerSlot drawer={false} />
                </div>
              )}
            </aside>
          </Panel>
        </Group>
      </Panel>
    </Group>
  );
}

/**
 * The console frame (plan §4.1, visual-polish S9/S10): top bar, stage rail, body, status bar.
 * The body is the landing card without a case, two columns on 접수·처리·보고 and three
 * (tree · grid · viewer) on 탐색·검토.
 * Landmarks: banner (top bar) · navigation (tree) · main (grid, #main) ·
 * complementary (viewer, #viewer, 탐색·검토 only) · contentinfo (status bar).
 */
export function Layout() {
  const drawer = useMediaQuery(DRAWER_QUERY);
  const setViewerIsDrawer = useAppStore((s) => s.setViewerIsDrawer);
  useEffect(() => setViewerIsDrawer(drawer), [drawer, setViewerIsDrawer]);
  const hasCase = useAppStore((s) => Boolean(s.route.runId));
  // The panel drawer exists only while a case (and so a panel) is open.
  const treeDrawer = useMediaQuery(TREE_DRAWER_QUERY) && hasCase;
  const setTreeIsDrawer = useAppStore((s) => s.setTreeIsDrawer);
  useEffect(() => setTreeIsDrawer(treeDrawer), [treeDrawer, setTreeIsDrawer]);
  const withViewer = useAppStore((s) => stageHasViewer(stageOf(s.route)));
  const columns = !hasCase ? "landing" : withViewer ? "three" : "two";
  // 클래식 분할 (AXIOM E3): grid above, viewer below — wide 탐색·검토 only.
  const classic = useViewPrefs((s) => s.classicSplit);

  return (
    <div
      className="shell"
      data-testid="workbench-shell"
      data-layout={drawer ? "drawer" : "wide"}
      data-tree={treeDrawer ? "drawer" : undefined}
      data-columns={columns}
      data-split={classic && columns === "three" && !drawer ? "classic" : undefined}
    >
      <SkipLink target={MAIN_ID} />
      <TopBar />
      <div className="shell-body">
        <StageRail />
        <div className="shell-panes">
          {columns === "landing" ? (
            <LandingPane />
          ) : columns === "two" ? (
            <TwoPanes narrow={drawer} treeDrawer={treeDrawer} />
          ) : drawer ? (
            <NarrowPanes treeDrawer={treeDrawer} />
          ) : classic ? (
            <ClassicPanes />
          ) : (
            <WidePanes />
          )}
        </div>
      </div>
      <StatusBar />
      <ToastRegion />
      <CommandPalette />
      <HelpOverlay />
      <ReviewToolsHost />
      <ActionsHost />
    </div>
  );
}
