import { type KeyboardEvent, type ReactNode, useEffect, useId, useRef } from "react";
import { Icon } from "../../icons";
import "./case.css";

const FIELD = "input:not([disabled]):not([type='hidden']), select:not([disabled]), textarea:not([disabled])";
const FOCUSABLE =
  "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";

/** Minimal accessible modal: labelled dialog, Esc closes, Tab is trapped, focus is restored. */
export function Modal({
  title,
  onClose,
  children,
  wide = false,
  footer,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
  /** Action row under a hairline (review #4): 취소 + the one primary action, right-aligned. */
  footer?: ReactNode;
}) {
  const titleId = useId();
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    // Start on the first form field (not the header's 닫기 button); no field → first focusable.
    const root = ref.current;
    const first =
      root?.querySelector<HTMLElement>(".case-modal-body")?.querySelector<HTMLElement>(FIELD) ??
      root?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? root)?.focus();
    return () => previous?.focus?.();
  }, []);

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.stopPropagation();
      onClose();
      return;
    }
    if (event.key !== "Tab" || !ref.current) return;
    const items = [...ref.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
    if (items.length === 0) return;
    const first = items[0] as HTMLElement;
    const last = items[items.length - 1] as HTMLElement;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };

  return (
    <div className="case-modal-backdrop">
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={`case-modal${wide ? " wide" : ""}`}
        onKeyDown={onKeyDown}
      >
        <header className="case-modal-header">
          <h2 id={titleId}>{title}</h2>
          <button type="button" className="icon-btn" aria-label="닫기" onClick={onClose}>
            <Icon name="close" />
          </button>
        </header>
        <div className="case-modal-body">{children}</div>
        {footer ? <footer className="case-modal-footer">{footer}</footer> : null}
      </div>
    </div>
  );
}
