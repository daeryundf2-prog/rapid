import { useEffect, useRef, useState } from "react";
import { Group, type GroupImperativeHandle, Panel, Separator } from "react-resizable-panels";
import { SkipLink, useEscape } from "../a11y";
import { focusMain, MAIN_ID, VIEWER_ID } from "../commands/builtin";
import { CommandButton } from "../commands/CommandButton";
import { Icon } from "../icons";
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
const DEFAULT_LAYOUT = { [PANEL.tree]: 20, [PANEL.grid]: 45, [PANEL.viewer]: 35 };

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
  return (
    <nav className="pane-frame" aria-label="탐색 트리" data-testid="tree-region">
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

function WidePanes() {
  const [saved, setSaved] = usePanelLayout();
  const groupRef = useRef<GroupImperativeHandle>(null);
  // The library reads `defaultLayout` before panels register; apply the saved
  // layout imperatively once after mount (same approach as the v2 workbench).
  // biome-ignore lint/correctness/useExhaustiveDependencies: mount-only initialisation
  useEffect(() => {
    const target = saved?.[PANEL.tree] && saved[PANEL.grid] && saved[PANEL.viewer] ? saved : DEFAULT_LAYOUT;
    groupRef.current?.setLayout(target);
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
      <Panel id={PANEL.tree} defaultSize="20%" minSize="240px" maxSize="320px">
        <TreePane />
      </Panel>
      <Separator className="resize-handle" />
      <Panel id={PANEL.grid} defaultSize="45%" minSize="320px">
        <GridPane />
      </Panel>
      <Separator className="resize-handle" />
      <Panel id={PANEL.viewer} defaultSize="35%" minSize="420px">
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
 * The console frame (plan §4.1): top bar, fixed 3-pane body, status bar.
 * Landmarks: banner (top bar) · navigation (tree) · main (grid, #main) ·
 * complementary (viewer, #viewer) · contentinfo (status bar).
 */
export function Layout() {
  const drawer = useMediaQuery(DRAWER_QUERY);
  const setViewerIsDrawer = useAppStore((s) => s.setViewerIsDrawer);
  useEffect(() => setViewerIsDrawer(drawer), [drawer, setViewerIsDrawer]);

  return (
    <div className="shell" data-testid="workbench-shell" data-layout={drawer ? "drawer" : "wide"}>
      <SkipLink target={MAIN_ID} />
      <TopBar />
      <div className="shell-body">{drawer ? <NarrowPanes /> : <WidePanes />}</div>
      <StatusBar />
      <CommandPalette />
      <HelpOverlay />
    </div>
  );
}
