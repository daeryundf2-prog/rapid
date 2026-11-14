import { type KeyboardEvent, useEffect, useRef, useState } from "react";
import { Icon } from "../icons";
import { type Route, stageOf } from "../router";
import { useAppStore } from "../state/store";
import { TOAST_MS, type ToastItem, useToastStore } from "./toastStore";
import "./toast.css";

/** KEY_MAP notation → aria-keyshortcuts notation ("Ctrl+Z" → "Control+Z"). */
export function ariaShortcut(shortcut: string): string {
  return shortcut.replace(/\bCtrl\b/g, "Control");
}

function ToastView({ toast }: { toast: ToastItem }) {
  const dismiss = useToastStore((s) => s.dismiss);
  // Hover / keyboard focus holds the timer so a toast never vanishes while it is being read.
  const [held, setHeld] = useState(false);
  useEffect(() => {
    if (toast.tone === "error" || held) return;
    // A toast with a link (a written file's 열기) stays twice as long: the analyst may want it.
    const timer = window.setTimeout(() => dismiss(toast.id), toast.action ? TOAST_MS * 2 : TOAST_MS);
    return () => window.clearTimeout(timer);
  }, [toast.id, toast.tone, toast.action, held, dismiss]);

  const close = () => {
    dismiss(toast.id);
    // The focused toast is gone: hand focus back to the page instead of <body>.
    document.getElementById("main")?.focus();
  };
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== "Escape") return;
    event.preventDefault();
    event.stopPropagation();
    close();
  };
  const action = toast.action;

  return (
    // biome-ignore lint/a11y/noStaticElementInteractions: Esc closes the toast the focus is in (its close button)
    <div
      className={`toast ${toast.tone}`}
      data-testid="toast"
      data-tone={toast.tone}
      onKeyDown={onKeyDown}
      onMouseEnter={() => setHeld(true)}
      onMouseLeave={() => setHeld(false)}
      onFocus={() => setHeld(true)}
      onBlur={() => setHeld(false)}
    >
      <span className="status-dot" aria-hidden="true" />
      <div className="toast-body">
        <span>{toast.text}</span>
        {toast.detail ? (
          <span className="toast-detail mono" data-testid="toast-detail">
            {toast.detail}
          </span>
        ) : null}
        {action?.href ? (
          <a
            className="toast-action"
            href={action.href}
            target="_blank"
            rel="noopener noreferrer"
            data-testid="toast-action"
          >
            {action.label}
          </a>
        ) : action?.run ? (
          <button
            type="button"
            className="toast-action view-link"
            data-testid="toast-action"
            // "실행 취소" (r8 T-036): the same key as the action, for screen readers and the tooltip.
            {...(action.shortcut
              ? {
                  "aria-keyshortcuts": ariaShortcut(action.shortcut),
                  title: `${action.label} (${action.shortcut})`,
                }
              : {})}
            onClick={() => {
              action.run?.();
              dismiss(toast.id);
            }}
          >
            {action.label}
          </button>
        ) : null}
      </div>
      <button type="button" className="icon-btn" aria-label="알림 닫기 (Esc)" onClick={close}>
        <Icon name="close" />
      </button>
    </div>
  );
}

/**
 * Error toasts belong to the screen they were raised on: a stage change, another case, or another
 * node / view of the same stage drops them (r7 L4, C-G12; E01 QA D2 — an export failure raised
 * in 보고 must not follow the analyst to every later screen). Row selection, filters and the
 * viewer do not count as a screen change. Info / ok toasts close on their own timer.
 */
export function screenKeyOf(route: Route): string {
  return [
    route.runId ?? "",
    stageOf(route),
    route.collection ?? "",
    route.kind ?? "",
    route.analysisId ?? "",
    route.view ?? "",
  ].join("|");
}

function useClearErrorsOnStageChange(): void {
  const stageKey = useAppStore((s) => screenKeyOf(s.route));
  const first = useRef(true);
  // biome-ignore lint/correctness/useExhaustiveDependencies: runs on every stage change
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    useToastStore.getState().clearErrors();
  }, [stageKey]);
}

/**
 * Bottom-right toast stack (visual-polish U-V7): max 3, non-errors close after 6 s, Esc closes
 * the focused one — and, with no dialog / menu open, the newest one (app.close). Deliberately not
 * a live region — see toastStore.ts.
 */
export function ToastRegion() {
  const toasts = useToastStore((s) => s.toasts);
  useClearErrorsOnStageChange();
  if (toasts.length === 0) return null;
  return (
    <div className="toast-region" data-testid="toast-region">
      {toasts.map((toast) => (
        <ToastView key={toast.id} toast={toast} />
      ))}
    </div>
  );
}
