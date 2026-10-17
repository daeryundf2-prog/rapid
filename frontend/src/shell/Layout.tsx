import { useEffect, useRef, useState } from "react";
import {
  Group,
  type GroupImperativeHandle,
  Panel,
  type PanelImperativeHandle,
  Separator,
} from "react-resizable-panels";
import { SkipLink, useEscape } from "../a11y";
import {
  expandViewerPane,
  focusMain,
  focusViewer,
  MAIN_ID,
  VIEWER_EXPAND_ID,
  VIEWER_ID,
} from "../commands/builtin";
import { CommandButton } from "../commands/CommandButton";
import { ToastRegion } from "../components/ToastRegion";
import { Landing } from "../features/case/Landing";
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

function TreePane() {
  // The left panel follows the stage (console-ia §3): domain tree, runs, review lists, exports.
  const label = useAppStore((s) => STAGE_DEFS[stageOf(s.route)].panelLabel);
  const stage = useAppStore((s) => (s.route.runId ? STAGE_DEFS[stageOf(s.route)].label : ""));
  return (
    <nav className="pane-frame" aria-label={label} data-testid="tree-region">
      {/* Stage switches (rail / Alt+1..5) land focus here (console-ia §3, Q-IA-1). */}
      <h1 id={STAGE_HEADING_ID} tabIndex={-1} className="stage-heading">
        {stage || "케이스"}
      </h1>
      <Slot name="tree" fallback={<p className="pane-empty">탐색 트리를 불러오는 중…</p>} />
    </nav>
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
function TwoPanes({ narrow }: { narrow: boolean }) {
  return (
    <Group id="rapidtriage-console-2col" orientation="horizontal" style={{ height: "100%" }}>
      <Panel id={PANEL.tree} defaultSize={narrow ? "28%" : TREE_DEFAULT} minSize="240px" maxSize="320px">
        <TreePane />
      </Panel>
      <Separator className="resize-handle" />
      <Panel id={PANEL.grid} minSize="320px">
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
      <Panel id={PANEL.tree} defaultSize={TREE_DEFAULT} minSize="240px" maxSize="320px">
        <TreePane />
      </Panel>
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

function NarrowPanes() {
  const open = useAppStore((s) => s.viewerDrawerOpen);
  const setOverlay = useAppStore((s) => s.setOverlay);
  const close = () => {
    setOverlay("viewerDrawer", false);
    focusMain();
  };
  useEscape(close, open);
  return (
    <>
      <Group id="rapidtriage-console-narrow" orientation="horizontal" style={{ height: "100%" }}>
        <Panel id={PANEL.tree} defaultSize="28%" minSize="240px" maxSize="320px">
          <TreePane />
        </Panel>
        <Separator className="resize-handle" />
        <Panel id={PANEL.grid} minSize="320px">
          <GridPane />
        </Panel>
      </Group>
      {open ? (
        <button type="button" className="drawer-scrim" aria-label="뷰어 닫기" tabIndex={-1} onClick={close} />
      ) : (
        <div className="drawer-handle">
          <CommandButton command="viewer.open" label="뷰어 열기" testId="viewer-drawer-open" />
        </div>
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
          <button
            type="button"
            className="button ghost icon-only"
            aria-label="뷰어 닫기 (Esc)"
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
  const withViewer = useAppStore((s) => stageHasViewer(stageOf(s.route)));
  const columns = !hasCase ? "landing" : withViewer ? "three" : "two";

  return (
    <div
      className="shell"
      data-testid="workbench-shell"
      data-layout={drawer ? "drawer" : "wide"}
      data-columns={columns}
    >
      <SkipLink target={MAIN_ID} />
      <TopBar />
      <div className="shell-body">
        <StageRail />
        <div className="shell-panes">
          {columns === "landing" ? (
            <LandingPane />
          ) : columns === "two" ? (
            <TwoPanes narrow={drawer} />
          ) : drawer ? (
            <NarrowPanes />
          ) : (
            <WidePanes />
          )}
        </div>
      </div>
      <StatusBar />
      <ToastRegion />
      <CommandPalette />
      <HelpOverlay />
    </div>
  );
}
