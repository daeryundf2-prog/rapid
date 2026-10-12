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
  /**
   * Also print the disabled reason as visible helper text beside the button (not only the
   * hover/focus tooltip). The sentence is already the button's description, so the visible
   * copy is aria-hidden.
   */
  showReason?: boolean;
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
  showReason,
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
  const button = (
    // With `showReason` the reason is printed below; a hover/focus box would draw it twice in
    // a second style (the 처리 card's 비교 reason looked like a button, 추출's like text).
    <DisabledReason reason={disabledReason} tooltip={!showReason}>
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
  if (!showReason || !disabledReason) return button;
  return (
    <span className="command-with-reason">
      {button}
      <span className="disabled-reason-text" aria-hidden="true" data-testid="command-disabled-reason">
        {disabledReason}
      </span>
    </span>
  );
}
