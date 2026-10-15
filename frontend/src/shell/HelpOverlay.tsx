import { useId, useRef } from "react";
import { useEscape, useFocusTrap } from "../a11y";
import { useCommands } from "../commands/registry";
import { Icon } from "../icons";
import { keyBindingRows, keyLabel } from "../shortcuts";
import { useAppStore } from "../state/store";

/** `?` — one page of every canonical key, generated from KEY_MAP + the live registry. */
export function HelpOverlay() {
  const open = useAppStore((s) => s.helpOpen);
  if (!open) return null;
  return <HelpDialog />;
}

function HelpDialog() {
  const setOverlay = useAppStore((s) => s.setOverlay);
  // Subscribe so the table follows (un)registrations while open.
  useCommands();
  const rows = keyBindingRows();
  const ref = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  const close = () => setOverlay("help", false);
  useFocusTrap(ref, { active: true, initialFocus: closeRef });
  useEscape(close);

  return (
    <div className="overlay-scrim" data-testid="help-overlay-scrim">
      <div
        ref={ref}
        className="help-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid="help-overlay"
      >
        <div className="dialog-head">
          <h2 id={titleId}>단축키</h2>
          <button
            ref={closeRef}
            type="button"
            className="button icon-only ghost"
            aria-label="닫기"
            onClick={close}
          >
            <Icon name="close" />
          </button>
        </div>
        <table className="help-table">
          <caption className="visually-hidden">단축키와 동작</caption>
          <thead>
            <tr>
              <th scope="col">키</th>
              <th scope="col">동작</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              // A key nothing is bound to right now is dimmed; its description says what it does.
              <tr
                key={row.name}
                className={row.commands.length ? undefined : "muted"}
                title={row.commands.length ? undefined : "해당 화면이 열려 있을 때 동작합니다"}
              >
                <td>
                  <kbd>{keyLabel(row.shortcut)}</kbd>
                </td>
                <td>{row.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="help-foot">
          모든 동작은 <kbd>{keyLabel("Ctrl+K")}</kbd> 명령 팔레트에서도 찾을 수 있습니다.
        </p>
      </div>
    </div>
  );
}
