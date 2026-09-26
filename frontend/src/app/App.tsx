import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import {
  Group,
  type GroupImperativeHandle,
  Panel,
  Separator,
  useDefaultLayout,
} from "react-resizable-panels";
import { ApiError, captureFragmentToken } from "../api/client";
import { listRuns } from "../api/runs";
import { RunDetailPane } from "../features/detail-panel/RunDetailPane";
import { CaseQueuePane } from "../features/evidence-tree/CaseQueuePane";
import { CollectionTablePane } from "../features/item-table/CollectionTablePane";
import { RunTablePane } from "../features/item-table/RunTablePane";
import { systemTheme, useUiStore } from "../state/ui";
import { TokenGate } from "./TokenGate";

export function App() {
  const theme = useUiStore((s) => s.theme);
  const toggleTheme = useUiStore((s) => s.toggleTheme);
  const selectedRunId = useUiStore((s) => s.selectedRunId);
  const selectedNode = useUiStore((s) => s.selectedNode);
  const [tokenVersion, setTokenVersion] = useState(0);

  useEffect(() => {
    if (captureFragmentToken()) {
      setTokenVersion((v) => v + 1);
    }
  }, []);

  const layout = useDefaultLayout({
    id: "rapidtriage-workbench",
    storage: window.localStorage,
    panelIds: ["queue", "items", "detail"],
    onlySaveAfterUserInteractions: true,
  });
  const groupRef = useRef<GroupImperativeHandle>(null);
  const savedLayout = layout.defaultLayout;
  // Apply the saved (or default) layout once after mount: the library's
  // defaultLayout prop is read before child panels register, so an
  // imperative setLayout is the reliable path.
  // biome-ignore lint/correctness/useExhaustiveDependencies: mount-only initialization
  useEffect(() => {
    const target =
      savedLayout && (savedLayout.queue ?? 0) + (savedLayout.detail ?? 0) > 0
        ? savedLayout
        : { queue: 20, items: 48, detail: 32 };
    groupRef.current?.setLayout(target);
  }, []);

  const runsQuery = useQuery({
    queryKey: ["runs", tokenVersion],
    queryFn: listRuns,
    refetchInterval: 5000,
  });

  const unauthorized =
    runsQuery.isError && runsQuery.error instanceof ApiError && runsQuery.error.status === 401;

  if (unauthorized) {
    return (
      <div className="workbench" data-testid="workbench-shell">
        <TokenGate onSaved={() => setTokenVersion((v) => v + 1)} />
      </div>
    );
  }

  const runs = runsQuery.data ?? [];
  const failedCount = runs.filter((r) => r.status === "failed").length;
  const activeTheme = theme ?? systemTheme();

  return (
    <div className="workbench" data-testid="workbench-shell">
      <header className="workbench-header">
        <span className="workbench-brand">RapidForensic</span>
        <span className="workbench-case-title">
          {selectedRunId ? `케이스 ${selectedRunId}` : "케이스를 선택하세요"}
        </span>
        <div className="header-search">
          <input type="search" placeholder="전체 검색 (Ctrl+K)" aria-label="전체 검색" />
          <button
            type="button"
            className="button"
            onClick={toggleTheme}
            title="테마 전환"
            data-testid="theme-toggle"
          >
            {activeTheme === "dark" ? "라이트" : "다크"}
          </button>
        </div>
      </header>
      <div className="workbench-body">
        <Group
          orientation="horizontal"
          groupRef={groupRef}
          onLayoutChanged={layout.onLayoutChanged}
          style={{ height: "100%" }}
        >
          <Panel id="queue" defaultSize="20%" minSize="160px" collapsible>
            <CaseQueuePane runs={runs} />
          </Panel>
          <Separator className="resize-handle" />
          <Panel id="items" defaultSize="48%" minSize="240px">
            {selectedNode ? <CollectionTablePane node={selectedNode} /> : <RunTablePane runs={runs} />}
          </Panel>
          <Separator className="resize-handle" />
          <Panel id="detail" defaultSize="32%" minSize="200px" collapsible>
            <RunDetailPane />
          </Panel>
        </Group>
      </div>
      <footer className="workbench-statusbar">
        <span data-testid="status-run-count">케이스 {runs.length}건</span>
        {failedCount > 0 && <span>실패 {failedCount}건</span>}
        {runsQuery.isError && <span>목록을 불러오지 못했습니다</span>}
        {runsQuery.isPending && <span>불러오는 중…</span>}
        <span style={{ marginLeft: "auto" }}>v2 workbench</span>
      </footer>
    </div>
  );
}
