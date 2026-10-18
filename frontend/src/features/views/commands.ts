/**
 * `view.*` commands (S9, plan X12; r4 §2.3): Alt+Shift+1–6 switch the explorer view
 * of the routed collection by writing `view=` (columns = no param). A view
 * the node cannot show reports its Korean reason instead of running.
 */

import { announce } from "../../a11y";
import { NO_RUN_REASON } from "../../commands/reasons";
import { registerCommands } from "../../commands/registry";
import type { Command } from "../../contracts/command";
import type { ExplorerView } from "../../router";
import { useAppStore } from "../../state/store";
import { VIEW_DEFS, viewDisabledReason } from "./availability";

export function switchView(view: ExplorerView): void {
  const state = useAppStore.getState();
  const next = view === "columns" ? undefined : view;
  if ((state.route.view ?? undefined) === next) return;
  state.patchRoute({ view: next });
}

export function viewCommands(): Command[] {
  return VIEW_DEFS.map(
    (def): Command => ({
      id: def.commandId,
      label: def.label,
      group: "grid",
      shortcut: def.shortcut,
      disabledReason: () => {
        const { route } = useAppStore.getState();
        if (!route.runId) return NO_RUN_REASON;
        return viewDisabledReason(def.id, { id: route.collection, kind: route.kind });
      },
      run: () => {
        switchView(def.id);
        announce(`${def.label}로 전환했습니다`);
      },
    }),
  );
}

/** Register the view commands; a second mount (StrictMode / tests) keeps the first registration. */
export function registerViewCommands(): () => void {
  try {
    return registerCommands(viewCommands());
  } catch (error) {
    console.warn(error instanceof Error ? error.message : error);
    return () => {};
  }
}
