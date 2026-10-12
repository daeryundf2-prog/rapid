import { useEffect, useRef, useState } from "react";
import { Group, type GroupImperativeHandle, Panel, Separator } from "react-resizable-panels";
import { SkipLink, useEscape } from "../a11y";
import { focusMain, MAIN_ID, VIEWER_ID } from "../commands/builtin";
import { CommandButton } from "../commands/CommandButton";
import { ToastRegion } from "../components/ToastRegion";
import { Landing } from "../features/case/Landing";
import { StageRail } from "../features/stages/StageRail";
import { STAGE_DEFS, STAGE_HEADING_ID } from "../features/stages/stages";
import { Icon } from "../icons";
import { stageHasViewer, stageOf } from "../router";
import { usePanelLayout } from "../state/hooks";
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
 * grid takes the rest — at 1440px that leaves ≈ 676px for 시각 · 유형 · 항목 · 경로 · 선별.
 * Every pane stays resizable; a dragged layout is saved (percentages) and restored.
 */
export const TREE_DEFAULT = "260px";
export const VIEWER_DEFAULT = "440px";

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

function WidePanes() {
  const [saved, setSaved] = usePanelLayout();
  const groupRef = useRef<GroupImperativeHandle>(null);
  // The library reads `defaultLayout` before panels register; apply a saved (dragged) layout
  // imperatively once after mount. Without one the panels' pixel defaults apply.
  // biome-ignore lint/correctness/useExhaustiveDependencies: mount-only initialisation
  useEffect(() => {
    if (saved?.[PANEL.tree] && saved[PANEL.grid] && saved[PANEL.viewer]) groupRef.current?.setLayout(saved);
  }, []);
  return (
    <Group
      id="rapidtriage-console"
      orientation="horizontal"
      groupRef={groupRef}
      onLayoutChanged={(layout, meta) => {
        if (meta?.isUserInteraction) setSaved({ ...layout });
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
      <Panel id={PANEL.viewer} defaultSize={VIEWER_DEFAULT} minSize="420px">
        <aside
          id={VIEWER_ID}
          tabIndex={-1}
          className="pane-frame"
          aria-label="뷰어 패널"
          data-testid="viewer-region"
        >
          <ViewerSlot drawer={false} />
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
