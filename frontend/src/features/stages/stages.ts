/**
 * Stage rail (console-ia §3): 접수 · 처리 · 탐색 · 검토 · 보고, Alt+1..5 (Ctrl+1..5 is browser tab switching). Each stage keeps
 * the last route the analyst had in it (per run), so switching stages and back returns to
 * the same view, row and filters. The top bar, viewer, status bar and key map stay global.
 */

import { announce } from "../../a11y";
import { NO_RUN_REASON } from "../../commands/builtin";
import { registerCommands } from "../../commands/registry";
import type { CollectionId } from "../../contracts/collection";
import type { Command } from "../../contracts/command";
import type { IconName } from "../../icons";
import { type Route, STAGES, type Stage, stageOf } from "../../router";
import { useAppStore } from "../../state/store";

export interface StageDef {
  id: Stage;
  label: string;
  icon: IconName;
  shortcut: string;
  /** Collection the stage opens on the first visit. */
  home: CollectionId;
  /** Accessible name of the stage's left panel. */
  panelLabel: string;
}

export const STAGE_DEFS: Record<Stage, StageDef> = {
  intake: {
    id: "intake",
    label: "접수",
    icon: "inbox",
    shortcut: "Alt+1",
    home: "intake",
    panelLabel: "탐색 트리",
  },
  process: {
    id: "process",
    label: "처리",
    icon: "cpu",
    shortcut: "Alt+2",
    home: "process",
    panelLabel: "처리 패널",
  },
  explore: {
    id: "explore",
    label: "탐색",
    icon: "search",
    shortcut: "Alt+3",
    home: "files",
    panelLabel: "탐색 트리",
  },
  review: {
    id: "review",
    label: "검토",
    icon: "flag",
    shortcut: "Alt+4",
    home: "review",
    panelLabel: "검토 패널",
  },
  report: {
    id: "report",
    label: "보고",
    icon: "report",
    shortcut: "Alt+5",
    home: "outputs",
    panelLabel: "보고 패널",
  },
};

/** Heading of the stage's left panel (Layout); stage switches move focus to it. */
export const STAGE_HEADING_ID = "stage-heading";

/** Last route per `${runId}|${stage}`. */
const lastRoutes = new Map<string, Route>();

export function rememberRoute(route: Route): void {
  if (!route.runId || !route.collection) return;
  lastRoutes.set(`${route.runId}|${stageOf(route)}`, route);
}

/** Tests only. */
export function resetStageMemory(): void {
  lastRoutes.clear();
}

/** Route a stage opens: the last one seen in it for this run, else its home view (keeping the viewer row). */
export function stageRoute(stage: Stage, current: Route): Route | null {
  if (!current.runId) return null;
  const remembered = lastRoutes.get(`${current.runId}|${stage}`);
  if (remembered) return remembered;
  const next: Route = { runId: current.runId, collection: STAGE_DEFS[stage].home };
  if (current.row) {
    next.row = current.row;
    if (current.mode) next.mode = current.mode;
  }
  return next;
}

export function openStage(stage: Stage): void {
  const store = useAppStore.getState();
  const next = stageRoute(stage, store.route);
  if (!next) return;
  store.navigate(next);
  // Focus the new stage's panel heading (tabindex=-1 h1) and say the stage name once.
  announce(`단계: ${STAGE_DEFS[stage].label}`, { hold: true });
  const focusHeading = () => document.getElementById(STAGE_HEADING_ID)?.focus();
  if (typeof window.requestAnimationFrame === "function") window.requestAnimationFrame(focusHeading);
  else focusHeading();
}

export function stageCommands(): Command[] {
  return STAGES.map((stage) => {
    const def = STAGE_DEFS[stage];
    return {
      id: `stage.${stage}`,
      label: `단계: ${def.label}`,
      group: "navigate",
      icon: def.icon,
      shortcut: def.shortcut,
      disabledReason: (ctx) => (ctx.runId ? undefined : NO_RUN_REASON),
      run: () => openStage(stage),
    };
  });
}

let unsubscribe: (() => void) | null = null;

/** Register the five stage commands and start remembering each stage's last route. */
export function registerStageCommands(): () => void {
  const off = registerCommands(stageCommands());
  rememberRoute(useAppStore.getState().route);
  unsubscribe?.();
  unsubscribe = useAppStore.subscribe((state, prev) => {
    if (state.route !== prev.route) rememberRoute(state.route);
  });
  return () => {
    off();
    unsubscribe?.();
    unsubscribe = null;
  };
}
