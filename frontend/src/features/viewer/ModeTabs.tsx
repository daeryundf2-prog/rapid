import { type KeyboardEvent, useRef } from "react";
import { DisabledReason } from "../../a11y";
import type { ViewerMode, ViewerModeState } from "../../contracts/viewer";
import { MODE_LABELS } from "./modes";

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
}

/**
 * WAI-ARIA tabs with automatic activation. Disabled modes stay focusable;
 * their reason lives only in S5's <DisabledReason> tooltip (aria-describedby).
 */
export function ModeTabs({ modes, active, onSelect }: ModeTabsProps) {
  const refs = useRef(new Map<ViewerMode, HTMLButtonElement>());

  const focusAt = (index: number) => {
    const count = modes.length;
    const next = modes[((index % count) + count) % count];
    if (!next) return;
    refs.current.get(next.mode)?.focus();
    if (next.available) onSelect(next.mode);
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

  return (
    <div className="viewer-tabs" role="tablist" aria-label="보기 모드" onKeyDown={onKeyDown}>
      {modes.map((state) => {
        const selected = state.mode === active;
        return (
          <DisabledReason key={state.mode} reason={state.available ? undefined : state.reason}>
            <button
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
          </DisabledReason>
        );
      })}
    </div>
  );
}
