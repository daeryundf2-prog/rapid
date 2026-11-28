import { type KeyboardEvent, useRef } from "react";
import type { ViewerMode, ViewerModeState } from "../../contracts/viewer";
import { MODE_LABELS, REASONS } from "./modes";

/** Id of the panel shown when there are no mode tabs (empty viewer). */
export const VIEWER_PANEL_ID = "viewer-panel";

export function tabId(mode: ViewerMode): string {
  return `viewer-tab-${mode}`;
}

/** Each tab controls its own tabpanel; only the active one is rendered visible. */
export function panelId(mode: ViewerMode): string {
  return `viewer-panel-${mode}`;
}

/**
 * The modes that are tabs (F25): the ones this row can show, 메타 first when the row points at a
 * decoded record (record first, hex second).
 */
export function tabModes(modes: readonly ViewerModeState[], recordFirst = false): ViewerModeState[] {
  const usable = modes.filter((m) => m.available);
  if (!recordFirst) return usable;
  const meta = usable.filter((m) => m.mode === "meta");
  return [...meta, ...usable.filter((m) => m.mode !== "meta")];
}

/** The modes this row cannot show, with their reasons (loading ones are not "cannot"). */
export function unusableModes(modes: readonly ViewerModeState[]): ViewerModeState[] {
  return modes.filter((m) => !m.available && m.reason !== REASONS.loading);
}

interface ModeTabsProps {
  modes: ViewerModeState[];
  active: ViewerMode;
  onSelect: (mode: ViewerMode) => void;
  recordFirst?: boolean;
}

/**
 * WAI-ARIA tabs with automatic activation over the modes this row can show. The modes it cannot
 * show are one 쓸 수 없는 보기 n disclosure after the tabs, each with its reason as text (F25: no
 * dimmed tab at 2.65:1, no reason that lives only in a tooltip).
 */
export function ModeTabs({ modes, active, onSelect, recordFirst = false }: ModeTabsProps) {
  const refs = useRef(new Map<ViewerMode, HTMLButtonElement>());
  const tabs = tabModes(modes, recordFirst);
  const unusable = unusableModes(modes);
  const loading = modes.some((m) => !m.available && m.reason === REASONS.loading);

  const focusAt = (index: number) => {
    const count = tabs.length;
    if (count === 0) return;
    const next = tabs[((index % count) + count) % count];
    if (!next) return;
    refs.current.get(next.mode)?.focus();
    onSelect(next.mode);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.altKey) return; // Alt+←/→ = viewer history.
    const current = tabs.findIndex(
      (m) => m.mode === (document.activeElement as HTMLElement | null)?.dataset.mode,
    );
    const index = current >= 0 ? current : tabs.findIndex((m) => m.mode === active);
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
        focusAt(tabs.length - 1);
        break;
      default:
        break;
    }
  };

  return (
    <div className="viewer-tabs-row">
      {/* No usable mode (no row yet): no empty tablist — the folded list below says why. */}
      {tabs.length ? (
        <div className="viewer-tabs" role="tablist" aria-label="보기 모드" onKeyDown={onKeyDown}>
          {tabs.map((state) => {
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
      ) : null}
      {unusable.length ? (
        <details className="viewer-tabs-unavailable" data-testid="viewer-unusable-modes">
          <summary>쓸 수 없는 보기 {unusable.length}</summary>
          <ul>
            {unusable.map((state) => (
              <li key={state.mode} data-mode={state.mode}>
                <strong>{MODE_LABELS[state.mode]}</strong>
                <span>{state.reason}</span>
              </li>
            ))}
          </ul>
        </details>
      ) : loading ? (
        <span className="viewer-tabs-unavailable viewer-tabs-loading">보기 확인 중…</span>
      ) : null}
    </div>
  );
}
