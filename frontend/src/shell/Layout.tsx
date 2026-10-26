import { useEffect, useRef, useState } from "react";
import {
  Group,
  type GroupImperativeHandle,
  Panel,
  type PanelImperativeHandle,
  Separator,
} from "react-resizable-panels";
import { SkipLink, useEscape, useFocusTrap } from "../a11y";
import {
  expandViewerPane,
  focusMain,
  focusViewer,
  MAIN_ID,
  TREE_EXPAND_ID,
  toggleTreePane,
  VIEWER_EXPAND_ID,
  VIEWER_ID,
} from "../commands/builtin";
import { CommandButton } from "../commands/CommandButton";
import { ToastRegion } from "../components/ToastRegion";
import { Landing } from "../features/case/Landing";
import { WriteConfirmHost } from "../features/case/WriteConfirm";
import { ReviewToolsHost } from "../features/review/ReviewToolsHost";
import { readClassicLayout, useViewPrefs, writeClassicLayout } from "../features/review/viewPrefs";
import { IntakePanel } from "../features/stages/IntakePanel";
import { StageRail } from "../features/stages/StageRail";
import { STAGE_DEFS, STAGE_HEADING_ID } from "../features/stages/stages";
import { focusPopout, returnViewerFromPopout, usePopoutHost } from "../features/viewer/popout/host";
import { Icon } from "../icons";
import { stageHasViewer, stageOf } from "../router";
import { usePanelLayout } from "../state/hooks";
import { viewerPaneCollapsed } from "../state/slices/overlays";
import { useAppStore } from "../state/store";
import { CommandPalette } from "./CommandPalette";
import { HelpOverlay } from "./HelpOverlay";
import { StatusBar } from "./StatusBar";
import { Slot } from "./slots";
import { TopBar } from "./TopBar";

/** Below this width the viewer becomes an overlay drawer (plan §4.1). */
export const DRAWER_QUERY = "(max-width: 1199.98px)";
/**
 * Below this width the left panel (tree) becomes an overlay drawer too (scroll review C2): the
 * stage rail, a 180px tree and a 320px grid no longer fit beside each other without widening the
 * page (body overflow is hidden, so the overflow was simply cut off).
 */
export const TREE_DRAWER_QUERY = "(max-width: 899.98px)";
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
/** The tree can be dragged from 180px to half the row, or past 180px shut to its rail (C2/C3). */
export const TREE_MIN = "180px";
export const TREE_MAX = "50%";
export const TREE_RAIL = "36px";
/** The grid keeps at least this much beside the tree (and the viewer). */
export const GRID_MIN = "320px";
export const VIEWER_DEFAULT = "440px";
/** Accessible names of the resize separators (UX-round review: every <Separator> has one). */
export const TREE_SEPARATOR_LABEL = "탐색 패널 너비 조절";
export const VIEWER_SEPARATOR_LABEL = "뷰어 너비 조절";
export const ROWS_SEPARATOR_LABEL = "목록·뷰어 높이 조절";
/** Width of the collapsed viewer rail (no row selected, or 뷰어 접기). */
export const VIEWER_RAIL = "36px";

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

function TreePane({ hidden = false }: { hidden?: boolean }) {
  // The left panel follows the stage (console-ia §3): domain tree, runs, review lists, exports.
  const label = useAppStore((s) => STAGE_DEFS[stageOf(s.route)].panelLabel);
  const stage = useAppStore((s) => (s.route.runId ? STAGE_DEFS[stageOf(s.route)].label : ""));
  const intake = useAppStore((s) => Boolean(s.route.runId) && stageOf(s.route) === "intake");
  return (
    <nav className="pane-frame" aria-label={label} data-testid="tree-region" hidden={hidden}>
      {/* Stage switches (rail / Alt+1..5) land focus here (console-ia §3, Q-IA-1). */}
      <h1 id={STAGE_HEADING_ID} tabIndex={-1} className="stage-heading">
        {stage || "케이스"}
      </h1>
      {/* 접수 has its own left panel (r7 L4, C-I3); every other stage the stage's tree slot. */}
      {intake ? (
        <IntakePanel />
      ) : (
        <Slot name="tree" fallback={<p className="pane-empty">탐색 트리를 불러오는 중…</p>} />
      )}
    </nav>
  );
}

/** The folded left panel (C2): a 36px rail whose button unfolds it, like the viewer's rail. */
function TreeRail() {
  return (
    <div className="viewer-rail tree-rail" data-testid="tree-rail">
      <button
        type="button"
        id={TREE_EXPAND_ID}
        className="viewer-rail-button"
        aria-label="왼쪽 패널 펼치기"
        aria-expanded={false}
        title="왼쪽 패널 펼치기"
        onClick={() => toggleTreePane()}
      >
        <span className="viewer-rail-icon">
          <Icon name="panel-left-open" />
        </span>
      </button>
    </div>
  );
}

/**
 * The left panel as a resizable Panel (≥ 900px): 180px … 50%, double-click on the handle resets
 * it to 260px, and dragging it past 180px folds it to the 36px rail (탐색 패널 접기 does the same).
 */
function TreePanel({ defaultSize = TREE_DEFAULT }: { defaultSize?: string }) {
  const panelRef = useRef<PanelImperativeHandle>(null);
  const collapsed = useAppStore((s) => s.treeCollapsed);
  const setCollapsed = useAppStore((s) => s.setTreeCollapsed);
  const [initiallyCollapsed] = useState(collapsed);
  useEffect(() => {
    const panel = panelRef.current;
    if (!panel) return;
    if (collapsed && !panel.isCollapsed()) panel.collapse();
    if (!collapsed && panel.isCollapsed()) {
      panel.expand();
      // A drag shut passes through the 180px minimum, which expand() would restore: reopen at
      // the default width instead.
      if (panel.isCollapsed() || panel.getSize().inPixels < 200) panel.resize(TREE_DEFAULT);
    }
  }, [collapsed]);
  return (
    <Panel
      id={PANEL.tree}
      panelRef={panelRef}
      defaultSize={initiallyCollapsed ? TREE_RAIL : defaultSize}
      minSize={TREE_MIN}
      maxSize={TREE_MAX}
      collapsible
      collapsedSize={TREE_RAIL}
      onResize={() => {
        // A drag across the fold threshold is the same choice as the rail / command.
        const shut = panelRef.current?.isCollapsed() ?? false;
        if (shut !== useAppStore.getState().treeCollapsed) setCollapsed(shut);
      }}
    >
      {collapsed ? <TreeRail /> : null}
      <TreePane hidden={collapsed} />
    </Panel>
  );
}

/** The stage rail's 탐색 button: where focus returns when the tree drawer closes. */
const TREE_TOGGLE_SELECTOR = '[data-testid="tree-toggle"]';
/** The narrow layout's 뷰어 열기 handle: where focus returns when the viewer drawer closes. */
const VIEWER_OPEN_SELECTOR = '[data-testid="viewer-drawer-open"]';

/**
 * After a drawer closes (UX-round review): once its focus trap has let go, move focus to `target()`
 * (else the list) when focus was left inside the now-hidden drawer or on <body>. Effects run after
 * the trap's cleanup in the same commit, so the trap cannot pull focus back.
 */
function useDrawerReturnFocus(
  open: boolean,
  ref: { current: HTMLElement | null },
  target: () => HTMLElement | null,
): void {
  const wasOpen = useRef(open);
  const targetRef = useRef(target);
  targetRef.current = target;
  useEffect(() => {
    const closing = wasOpen.current && !open;
    wasOpen.current = open;
    if (!closing) return;
    const active = document.activeElement;
    const stranded = !active || active === document.body || (ref.current?.contains(active) ?? false);
    if (!stranded) return;
    targetRef.current()?.focus();
    // No target, or one that cannot take focus (a disabled handle): the list.
    if (document.activeElement === active || document.activeElement === document.body) focusMain();
  }, [open, ref]);
}

/**
 * Below 900px the left panel is an overlay drawer from the left edge (C2), opened from the stage
 * rail's 탐색 패널 button (or the command); Esc, the scrim or picking a node closes it. While open
 * it traps focus (initial focus on the stage heading, UX-round review); closing returns focus to
 * the 탐색 button, or to the list when a picked node closed it.
 */
function TreeDrawer() {
  const open = useAppStore((s) => s.treeDrawerOpen);
  const setOverlay = useAppStore((s) => s.setOverlay);
  const drawerRef = useRef<HTMLDivElement>(null);
  const pickedNode = useRef(false);
  const close = () => setOverlay("treeDrawer", false);
  useEscape(close, open);
  useFocusTrap(drawerRef, { active: open, initialFocus: `#${STAGE_HEADING_ID}`, returnFocus: false });
  useDrawerReturnFocus(open, drawerRef, () => {
    const picked = pickedNode.current;
    pickedNode.current = false;
    return picked ? null : document.querySelector<HTMLElement>(TREE_TOGGLE_SELECTOR);
  });
  // Picking a node (another collection / kind / stage) closes the drawer: the list is the goal.
  const place = useAppStore(
    (s) => `${s.route.runId}|${s.route.collection}|${s.route.kind ?? ""}|${s.route.status ?? ""}`,
  );
  const lastPlace = useRef(place);
  useEffect(() => {
    if (place === lastPlace.current) return;
    lastPlace.current = place;
    if (useAppStore.getState().treeDrawerOpen) {
      pickedNode.current = true;
      setOverlay("treeDrawer", false);
    }
  }, [place, setOverlay]);
  return (
    <>
      {open ? (
        <button
          type="button"
          className="drawer-scrim"
          aria-label="왼쪽 패널 닫기"
          tabIndex={-1}
          onClick={close}
        />
      ) : null}
      <div
        ref={drawerRef}
        className={`tree-drawer${open ? " open" : ""}`}
        data-testid="tree-drawer"
        role="dialog"
        aria-modal="true"
        aria-label="탐색 패널"
        hidden={!open}
      >
        <div className="drawer-head">
          <button
            type="button"
            className="button ghost icon-only"
            aria-label="왼쪽 패널 닫기 (Esc)"
            onClick={close}
          >
            <Icon name="close" />
          </button>
        </div>
        <TreePane />
      </div>
    </>
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

/** 접수·처리·보고: left panel + page, no viewer column. */
function TwoPanes({ narrow, treeDrawer }: { narrow: boolean; treeDrawer: boolean }) {
  // The tree drawer itself is the Layout's (it outlives the 2 ↔ 3 column switch).
  if (treeDrawer) return <GridPane />;
  return (
    <Group id="rapidtriage-console-2col" orientation="horizontal" style={{ height: "100%" }}>
      <TreePanel defaultSize={narrow ? "28%" : TREE_DEFAULT} />
      <Separator className="resize-handle" aria-label={TREE_SEPARATOR_LABEL} />
      <Panel id={PANEL.grid} minSize={GRID_MIN}>
        <GridPane />
      </Panel>
    </Group>
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
  // The library reads `defaultLayout` before panels register; apply a saved (dragged) layout
  // imperatively once after mount. Without one the panels' pixel defaults apply.
  // biome-ignore lint/correctness/useExhaustiveDependencies: mount-only initialisation
  useEffect(() => {
    if (validLayout(saved) && !initiallyCollapsed) groupRef.current?.setLayout(saved);
  }, []);
  // Collapse to the rail / expand back to the saved (dragged) width, else the 440px default.
  useEffect(() => {
    const panel = viewerRef.current;
    if (!panel) return;
    if (collapsed) {
      if (!panel.isCollapsed()) panel.collapse();
      return;
    }
    if (!panel.isCollapsed()) return;
    const layout = savedRef.current;
    if (validLayout(layout)) groupRef.current?.setLayout(layout);
    if (panel.isCollapsed()) panel.resize(VIEWER_DEFAULT);
  }, [collapsed]);
  return (
    <Group
      id="rapidtriage-console"
      orientation="horizontal"
      groupRef={groupRef}
      onLayoutChanged={(layout, meta) => {
        if (!meta?.isUserInteraction) return;
        const draggedShut = viewerRef.current?.isCollapsed() ?? false;
        // A drag across the collapse threshold is the same choice as the buttons.
        if (draggedShut !== collapsedRef.current) setViewerPane(draggedShut ? "collapsed" : "open");
        // Only an expanded viewer's width is worth restoring.
        if (!draggedShut) setSaved({ ...layout });
      }}
      style={{ height: "100%" }}
    >
      <TreePanel />
      <Separator className="resize-handle" aria-label={TREE_SEPARATOR_LABEL} />
      <Panel id={PANEL.grid} minSize={GRID_MIN}>
        <GridPane />
      </Panel>
      <Separator className="resize-handle" aria-label={VIEWER_SEPARATOR_LABEL} />
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

function NarrowPanes({ treeDrawer }: { treeDrawer: boolean }) {
  const open = useAppStore((s) => s.viewerDrawerOpen);
  const setOverlay = useAppStore((s) => s.setOverlay);
  const drawerRef = useRef<HTMLElement>(null);
  const close = () => setOverlay("viewerDrawer", false);
  useEscape(close, open);
  // Like the tree drawer (UX-round review): trapped while open; closing returns focus to where it
  // was before (e.g. the row), else to the 뷰어 열기 handle, else to the list.
  // Opening lands on the drawer's 닫기 button (review P8: it used to land on the metadata block).
  useFocusTrap(drawerRef, { active: open, initialFocus: "[data-viewer-drawer-close]" });
  useDrawerReturnFocus(open, drawerRef, () => document.querySelector<HTMLElement>(VIEWER_OPEN_SELECTOR));
  return (
    <>
      {treeDrawer ? (
        <GridPane />
      ) : (
        <Group id="rapidtriage-console-narrow" orientation="horizontal" style={{ height: "100%" }}>
          <TreePanel defaultSize="28%" />
          <Separator className="resize-handle" aria-label={TREE_SEPARATOR_LABEL} />
          <Panel id={PANEL.grid} minSize={GRID_MIN}>
            <GridPane />
          </Panel>
        </Group>
      )}
      {open ? (
        <button type="button" className="drawer-scrim" aria-label="뷰어 닫기" tabIndex={-1} onClick={close} />
      ) : (
        <div className="drawer-handle">
          <CommandButton command="viewer.open" label="뷰어 열기" testId="viewer-drawer-open" />
        </div>
      )}
      <aside
        ref={drawerRef}
        id={VIEWER_ID}
        tabIndex={-1}
        className={`viewer-drawer${open ? " open" : ""}`}
        aria-label="뷰어 패널"
        data-testid="viewer-region"
        hidden={!open}
      >
        <div className="drawer-head">
          <button
            type="button"
            className="button ghost icon-only"
            aria-label="뷰어 닫기 (Esc)"
            data-viewer-drawer-close=""
            onClick={close}
          >
            <Icon name="close" />
          </button>
        </div>
        <ViewerSlot drawer />
      </aside>
    </>
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
  return (
    <Group id="rapidtriage-console-classic" orientation="horizontal" style={{ height: "100%" }}>
      <TreePanel />
      <Separator className="resize-handle" aria-label={TREE_SEPARATOR_LABEL} />
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
          <Separator className="resize-handle resize-handle-rows" aria-label={ROWS_SEPARATOR_LABEL} />
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
  const treeDrawer = useMediaQuery(TREE_DRAWER_QUERY);
  const setTreeIsDrawer = useAppStore((s) => s.setTreeIsDrawer);
  useEffect(() => setTreeIsDrawer(treeDrawer), [treeDrawer, setTreeIsDrawer]);
  const hasCase = useAppStore((s) => Boolean(s.route.runId));
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
          {treeDrawer && columns !== "landing" ? <TreeDrawer /> : null}
        </div>
      </div>
      <StatusBar />
      <ToastRegion />
      <WriteConfirmHost />
      <CommandPalette />
      <HelpOverlay />
      <ReviewToolsHost />
    </div>
  );
}
