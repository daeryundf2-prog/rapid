import { DisabledReason } from "../../a11y/primitives";
import { toggleTreePane } from "../../commands/builtin";
import { useCommandState } from "../../commands/registry";
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

/** Vertical stage rail (console-ia §3): always visible, one button per stage, Alt+1..5 (Ctrl+1..5 is browser tab switching). */
export function StageRail() {
  const stage = useAppStore((s) => (s.route.runId ? stageOf(s.route) : null));
  // No case: every stage is disabled (each button says why); the rail recedes (review #14).
  const hasCase = useAppStore((s) => Boolean(s.route.runId));
  return (
    <nav
      className="stage-rail"
      aria-label="작업 단계"
      data-testid="stage-rail"
      data-disabled={hasCase ? undefined : ""}
    >
      <ul>
        {STAGES.map((id) => (
          <RailButton key={id} stage={id} current={stage === id} />
        ))}
      </ul>
      {hasCase ? <TreeToggle /> : null}
    </nav>
  );
}

/**
 * 패널 (scroll review C2, r7 C-G10): opens / closes the left-panel drawer below 900px, folds / unfolds
 * the left panel wider. Sits at the foot of the rail, apart from the stage buttons.
 */
function TreeToggle() {
  const drawer = useAppStore((s) => s.treeIsDrawer);
  const shown = useAppStore((s) => (s.treeIsDrawer ? s.treeDrawerOpen : !s.treeCollapsed));
  // "패널" (C-G10): the word 탐색 is the 탐색 stage right above; this folds the LEFT panel of any stage.
  const label = drawer
    ? shown
      ? "왼쪽 패널 닫기"
      : "왼쪽 패널 열기"
    : shown
      ? "왼쪽 패널 접기"
      : "왼쪽 패널 펼치기";
  return (
    <button
      type="button"
      className="stage-rail-item stage-rail-tree"
      aria-expanded={shown}
      aria-label={label}
      title={label}
      data-testid="tree-toggle"
      onClick={() => toggleTreePane()}
    >
      <Icon name={shown ? "sidebar" : "panel-left-open"} />
      <span className="stage-rail-label">패널</span>
    </button>
  );
}
