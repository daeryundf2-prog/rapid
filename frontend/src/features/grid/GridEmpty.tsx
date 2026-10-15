import { CommandButton } from "../../commands/CommandButton";
import { useCommandState } from "../../commands/registry";
import { Icon, type IconName } from "../../icons";

export interface GridEmptyAction {
  /** Registered command id; the button is left out while it is not registered. */
  command: string;
  label: string;
}

export interface GridEmptyState {
  icon: IconName;
  /** One sentence. */
  text: string;
  action?: GridEmptyAction;
}

function EmptyAction({ action }: { action: GridEmptyAction }) {
  const { command } = useCommandState(action.command);
  if (!command) return null;
  return <CommandButton command={action.command} label={`${action.label} →`} variant="ghost" />;
}

/**
 * Grid empty state (visual-polish U-V6): icon + one sentence + the next action. Plain text (the
 * shell's single announce() region speaks result counts); the button is a normal command view.
 */
export function GridEmpty({ state, testId }: { state: GridEmptyState; testId?: string }) {
  return (
    <div className="grid-empty" data-testid={testId}>
      <span className="grid-empty-icon" aria-hidden="true">
        <Icon name={state.icon} />
      </span>
      <p className="grid-empty-text">{state.text}</p>
      {state.action ? <EmptyAction action={state.action} /> : null}
    </div>
  );
}
