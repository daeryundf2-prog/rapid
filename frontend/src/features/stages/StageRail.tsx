import { DisabledReason } from "../../a11y/primitives";
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
  return (
    <nav className="stage-rail" aria-label="작업 단계" data-testid="stage-rail">
      <ul>
        {STAGES.map((id) => (
          <RailButton key={id} stage={id} current={stage === id} />
        ))}
      </ul>
    </nav>
  );
}
