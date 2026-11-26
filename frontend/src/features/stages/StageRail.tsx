import { DisabledReason } from "../../a11y/primitives";
import { TREE_DRAWER_ID, TREE_TOGGLE_ID } from "../../commands/builtin";
import { useCommandState } from "../../commands/registry";
import { KEY_MAP } from "../../contracts/command";
import { Icon } from "../../icons";
import { STAGES, type Stage, stageOf } from "../../router";
import { keyLabel } from "../../shortcuts";
import { useAppStore } from "../../state/store";
import { STAGE_DEFS } from "./stages";
import "./stages.css";

function RailButton({ stage, current }: { stage: Stage; current: boolean }) {
  const def = STAGE_DEFS[stage];
  const { disabledReason, run } = useCommandState(`stage.${stage}`);
  return (
    <li>
      <DisabledReason reason={disabledReason}>
        <button
          type="button"
          className={`stage-rail-item${current ? " is-current" : ""}`}
          aria-current={current ? "page" : undefined}
          aria-keyshortcuts={def.shortcut.replace("Ctrl", "Control")}
          title={disabledReason ? undefined : `${def.label} (${keyLabel(def.shortcut)})`}
          data-stage={stage}
          onClick={() => {
            void run();
          }}
        >
          <Icon name={def.icon} />
          <span className="stage-rail-label">{def.label}</span>
        </button>
      </DisabledReason>
    </li>
  );
}

/**
 * Narrow layout (< 900px): the stage's left panel is a drawer and this button, above the stages,
 * shows or hides it (Alt+0). Its name is the panel's (탐색 트리 · 처리 패널 …); the face is its last word.
 */
function PanelToggle() {
  const open = useAppStore((s) => s.treeDrawerOpen);
  const panel = useAppStore((s) => STAGE_DEFS[stageOf(s.route)].panelLabel);
  const { run } = useCommandState("tree.panel");
  return (
    <div className="stage-rail-panel">
      <button
        type="button"
        id={TREE_TOGGLE_ID}
        className="stage-rail-item"
        data-testid="tree-drawer-toggle"
        aria-label={panel}
        aria-expanded={open}
        aria-controls={TREE_DRAWER_ID}
        aria-keyshortcuts={KEY_MAP.treePanel}
        title={`${panel} ${open ? "닫기" : "열기"} (${keyLabel(KEY_MAP.treePanel)})`}
        onClick={() => {
          void run();
        }}
      >
        <Icon name="sidebar" />
        <span className="stage-rail-label">{panel.split(" ").pop()}</span>
      </button>
    </div>
  );
}

/** Vertical stage rail (console-ia §3): always visible, one button per stage, Alt+1..5 (Ctrl+1..5 is browser tab switching). */
export function StageRail() {
  const stage = useAppStore((s) => (s.route.runId ? stageOf(s.route) : null));
  // No case: every stage is disabled (each button says why); the rail recedes (review #14).
  const hasCase = useAppStore((s) => Boolean(s.route.runId));
  const panelIsDrawer = useAppStore((s) => s.treeIsDrawer);
  return (
    <nav
      className="stage-rail"
      aria-label="작업 단계"
      data-testid="stage-rail"
      data-disabled={hasCase ? undefined : ""}
    >
      {panelIsDrawer ? <PanelToggle /> : null}
      <ul>
        {STAGES.map((id) => (
          <RailButton key={id} stage={id} current={stage === id} />
        ))}
      </ul>
    </nav>
  );
}
