/**
 * View switcher above the grid (S9, plan X6/X12): 열 보기 / 썸네일 보기 /
 * 대화 보기 / 히스토그램 보기. The active view lives in the URL (`view=`),
 * Alt+Shift+1–4 run the `view.*` commands, and views the routed node cannot
 * show are disabled with their reason. The column view renders `children`
 * (the DataGrid) unchanged.
 */

import { type ReactNode, useEffect } from "react";
import { DisabledReason } from "../a11y";
import { effectiveView, VIEW_DEFS, viewAvailability } from "../features/views/availability";
import { ChatView } from "../features/views/ChatView";
import { registerViewCommands, switchView } from "../features/views/commands";
import { HistogramView } from "../features/views/HistogramView";
import { ThumbnailView } from "../features/views/ThumbnailView";
import { keyLabel } from "../shortcuts";
import { useRoute } from "../state/hooks";
import "../features/views/views.css";

export function ViewSwitch({ children }: { children: ReactNode }) {
  const { route, view, patchRoute } = useRoute();
  const scope = { id: route.collection, kind: route.kind };
  const availability = viewAvailability(scope);
  const active = effectiveView(view, scope);
  const showBar = Boolean(route.runId && route.collection && route.collection !== "intake");

  useEffect(() => registerViewCommands(), []);

  // A `view=` the node cannot show (stale link, node changed) is dropped from the URL.
  useEffect(() => {
    if (route.view && route.view !== active) patchRoute({ view: undefined }, { replace: true });
  }, [route.view, active, patchRoute]);

  return (
    <div className="view-switch-host">
      {showBar ? (
        <div className="view-switch" role="toolbar" aria-label="보기 전환">
          {VIEW_DEFS.map((def) => (
            <DisabledReason key={def.id} reason={availability[def.id]}>
              <button
                type="button"
                className="view-switch-button"
                aria-pressed={active === def.id}
                aria-keyshortcuts={def.shortcut}
                title={`${def.label} (${keyLabel(def.shortcut)})`}
                onClick={() => switchView(def.id)}
              >
                {def.label}
              </button>
            </DisabledReason>
          ))}
        </div>
      ) : null}
      <div className="view-switch-body">
        {active === "thumbnails" ? (
          <ThumbnailView />
        ) : active === "chat" ? (
          <ChatView />
        ) : active === "histogram" ? (
          <HistogramView />
        ) : (
          children
        )}
      </div>
    </div>
  );
}
