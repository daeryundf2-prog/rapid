/**
 * View switcher above the grid (S9, plan X6/X12; r4 §2.3): 열 보기 / 썸네일 보기 /
 * 대화 보기 / 히스토그램 보기 / 행(카드) 보기 / 지도 대체 보기. The active view lives in the URL
 * (`view=`), Alt+Shift+1–6 run the `view.*` commands, and views the routed node cannot
 * show are disabled with their reason. The column view renders `children`
 * (the DataGrid) unchanged and hands the switch to its filter-bar line
 * (visual-polish S1); a node with only the column view shows no switch (S2).
 */

import { type ReactNode, useEffect } from "react";
import { DisabledReason } from "../a11y";
import { effectiveView, VIEW_DEFS, viewAvailability } from "../features/views/availability";
import { CardView } from "../features/views/CardView";
import { ChatView } from "../features/views/ChatView";
import { registerViewCommands, switchView } from "../features/views/commands";
import { HistogramView } from "../features/views/HistogramView";
import { MapView } from "../features/views/MapView";
import { ThumbnailView } from "../features/views/ThumbnailView";
import { ToolbarLeadContext } from "../features/views/toolbarSlot";
import { Icon, type IconName } from "../icons";
import type { ExplorerView } from "../router";
import { keyLabel } from "../shortcuts";
import { useRoute } from "../state/hooks";
import "../features/views/views.css";

const VIEW_ICONS: Record<ExplorerView, IconName> = {
  columns: "columns",
  thumbnails: "image",
  chat: "message",
  histogram: "bar-chart",
  cards: "list",
  map: "map-pin",
};

export function ViewSwitch({ children }: { children: ReactNode }) {
  const { route, view, patchRoute } = useRoute();
  const scope = { id: route.collection, kind: route.kind };
  const availability = viewAvailability(scope);
  const active = effectiveView(view, scope);
  // A node that can only show the column view (리뷰보드, 산출물) gets no switch at all (S2).
  const onlyColumns = VIEW_DEFS.every((def) => def.id === "columns" || Boolean(availability[def.id]));
  const showBar = Boolean(route.runId && route.collection && route.collection !== "intake") && !onlyColumns;

  useEffect(() => registerViewCommands(), []);

  // A `view=` the node cannot show (stale link, node changed) is dropped from the URL.
  useEffect(() => {
    if (route.view && route.view !== active) patchRoute({ view: undefined }, { replace: true });
  }, [route.view, active, patchRoute]);

  // A compact icon segment (visual-polish S1); the label is each button's name and tooltip.
  const bar = showBar ? (
    <div className="view-switch segmented" role="toolbar" aria-label="보기 전환">
      {VIEW_DEFS.map((def) => (
        <DisabledReason key={def.id} reason={availability[def.id]}>
          <button
            type="button"
            className="view-switch-button"
            aria-label={def.label}
            aria-pressed={active === def.id}
            aria-keyshortcuts={def.shortcut}
            title={`${def.label} (${keyLabel(def.shortcut)})`}
            onClick={() => switchView(def.id)}
          >
            <Icon name={VIEW_ICONS[def.id]} />
          </button>
        </DisabledReason>
      ))}
    </div>
  ) : null;

  return (
    <div className="view-switch-host">
      {active !== "columns" && bar ? <div className="view-switch-row">{bar}</div> : null}
      <div className="view-switch-body">
        {active === "thumbnails" ? (
          <ThumbnailView />
        ) : active === "chat" ? (
          <ChatView />
        ) : active === "histogram" ? (
          <HistogramView />
        ) : active === "cards" ? (
          <CardView />
        ) : active === "map" ? (
          <MapView />
        ) : (
          // The column view: the switch sits on the grid's filter-bar line.
          <ToolbarLeadContext.Provider value={bar}>{children}</ToolbarLeadContext.Provider>
        )}
      </div>
    </div>
  );
}
