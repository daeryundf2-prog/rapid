import { DisabledReason } from "../a11y";
import { Icon, isIconName } from "../icons";
import { keyLabel } from "../shortcuts";
import { useCommandState } from "./registry";

export interface CommandButtonProps {
  /** Registered command id. */
  command: string;
  /** Visible text; defaults to the command label. Icon-only when `iconOnly`. */
  label?: string;
  iconOnly?: boolean;
  variant?: "default" | "primary" | "ghost";
  className?: string;
  /** Extra attributes for tests / e2e. */
  testId?: string;
}

/**
 * A button is a view of a Command (contracts/command.ts): it runs the command
 * or, when `disabledReason` is set, stays focusable with aria-disabled and a
 * reason tooltip (a11y DisabledReason).
 */
export function CommandButton({
  command,
  label,
  iconOnly,
  variant = "default",
  className,
  testId,
}: CommandButtonProps) {
  const { command: cmd, disabledReason, run } = useCommandState(command);
  const text = label ?? cmd?.label ?? command;
  const hint = cmd?.shortcut ? `${text} (${keyLabel(cmd.shortcut)})` : text;
  const classes = [
    "button",
    variant !== "default" ? variant : "",
    iconOnly ? "icon-only" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <DisabledReason reason={disabledReason}>
      <button
        type="button"
        className={classes}
        data-command={command}
        data-testid={testId}
        aria-label={iconOnly ? text : undefined}
        aria-keyshortcuts={cmd?.shortcut}
        title={disabledReason ? undefined : hint}
        onClick={() => {
          void run();
        }}
      >
        {cmd?.icon && isIconName(cmd.icon) ? <Icon name={cmd.icon} /> : null}
        {iconOnly ? null : <span>{text}</span>}
      </button>
    </DisabledReason>
  );
}
