import { type KeyboardEvent, useRef } from "react";
import type { ViewerMode, ViewerModeState } from "../../contracts/viewer";
import { MODE_LABELS, type ModeNotice, visibleModes } from "./modes";

/** Id of the panel shown when there are no mode tabs (empty viewer). */
export const VIEWER_PANEL_ID = "viewer-panel";

export function tabId(mode: ViewerMode): string {
  return `viewer-tab-${mode}`;
}

/** Each tab controls its own tabpanel; only the active one is rendered visible. */
export function panelId(mode: ViewerMode): string {
  return `viewer-panel-${mode}`;
}

interface ModeTabsProps {
  modes: ViewerModeState[];
  active: ViewerMode;
  onSelect: (mode: ViewerMode) => void;
  /** Content that cannot be shown: one sentence + one alternative beside the tabs (r8 T-086). */
  notice?: ModeNotice | null;
}

/**
 * WAI-ARIA tabs with automatic activation. Only usable modes are tabs (r8 T-086, IS-024: a tab
 * that leads nowhere is a dead end); when the content itself cannot be shown, the strip says why
 * in one sentence and offers one alternative.
 */
export function ModeTabs({ modes: all, active, onSelect, notice }: ModeTabsProps) {
  const refs = useRef(new Map<ViewerMode, HTMLButtonElement>());
  const modes = visibleModes(all);

  const focusAt = (index: number) => {
    const count = modes.length;
    const next = modes[((index % count) + count) % count];
    if (!next) return;
    refs.current.get(next.mode)?.focus();
    onSelect(next.mode);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.altKey) return; // Alt+←/→ = viewer history.
    const current = modes.findIndex(
      (m) => m.mode === (document.activeElement as HTMLElement | null)?.dataset.mode,
    );
    const index = current >= 0 ? current : modes.findIndex((m) => m.mode === active);
    switch (event.key) {
      case "ArrowRight":
        event.preventDefault();
        focusAt(index + 1);
        break;
      case "ArrowLeft":
        event.preventDefault();
        focusAt(index - 1);
        break;
      case "Home":
        event.preventDefault();
        focusAt(0);
        break;
      case "End":
        event.preventDefault();
        focusAt(modes.length - 1);
        break;
      default:
        break;
    }
  };

  const action = notice?.action ?? null;
  return (
    <>
      <div className="viewer-tabs" role="tablist" aria-label="보기 모드" onKeyDown={onKeyDown}>
        {modes.map((state) => {
          const selected = state.mode === active;
          return (
            <button
              key={state.mode}
              ref={(element) => {
                if (element) refs.current.set(state.mode, element);
                else refs.current.delete(state.mode);
              }}
              type="button"
              role="tab"
              id={tabId(state.mode)}
              data-mode={state.mode}
              className="viewer-tab"
              aria-selected={selected}
              data-viewer-focus={selected ? "" : undefined}
              // Every tab controls its own panel (inactive panels are rendered `hidden`
              // and empty), and each panel is labelled by its tab.
              aria-controls={panelId(state.mode)}
              tabIndex={selected ? 0 : -1}
              onClick={() => onSelect(state.mode)}
            >
              {MODE_LABELS[state.mode]}
            </button>
          );
        })}
      </div>
      {notice ? (
        <p className="viewer-tab-notice" data-testid="viewer-tab-notice">
          {notice.text}
          {action ? (
            <>
              {" — "}
              <button
                type="button"
                className="viewer-tab-notice-action"
                data-testid="viewer-tab-notice-action"
                onClick={() => {
                  onSelect(action.mode);
                  refs.current.get(action.mode)?.focus();
                }}
              >
                {action.label}
              </button>
            </>
          ) : null}
        </p>
      ) : null}
    </>
  );
}
