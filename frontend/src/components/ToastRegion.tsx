import { type KeyboardEvent, useEffect, useState } from "react";
import { Icon } from "../icons";
import { TOAST_MS, type ToastItem, useToastStore } from "./toastStore";

function ToastView({ toast }: { toast: ToastItem }) {
  const dismiss = useToastStore((s) => s.dismiss);
  // Hover / keyboard focus holds the timer so a toast never vanishes while it is being read.
  const [held, setHeld] = useState(false);
  useEffect(() => {
    if (toast.tone === "error" || held) return;
    const timer = window.setTimeout(() => dismiss(toast.id), TOAST_MS);
    return () => window.clearTimeout(timer);
  }, [toast.id, toast.tone, held, dismiss]);

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
      <div className="toast-body">{toast.text}</div>
      <button type="button" className="icon-btn" aria-label="알림 닫기 (Esc)" onClick={close}>
        <Icon name="close" />
      </button>
    </div>
  );
}

/**
 * Bottom-right toast stack (visual-polish U-V7): max 3, non-errors close after 6 s, Esc closes
 * the focused one. Deliberately not a live region — see toastStore.ts.
 */
export function ToastRegion() {
  const toasts = useToastStore((s) => s.toasts);
  if (toasts.length === 0) return null;
  return (
    <div className="toast-region" data-testid="toast-region">
      {toasts.map((toast) => (
        <ToastView key={toast.id} toast={toast} />
      ))}
    </div>
  );
}
