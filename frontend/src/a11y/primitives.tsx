import {
  type CSSProperties,
  cloneElement,
  type MouseEvent,
  type ReactElement,
  type ReactNode,
  useId,
  useState,
  useSyncExternalStore,
} from "react";
import { getAnnouncerSnapshot, subscribeAnnouncer } from "./announcer";

export const visuallyHiddenStyle: CSSProperties = {
  position: "absolute",
  width: 1,
  height: 1,
  margin: -1,
  padding: 0,
  overflow: "hidden",
  clip: "rect(0 0 0 0)",
  clipPath: "inset(50%)",
  whiteSpace: "nowrap",
  border: 0,
};

export function VisuallyHidden({ children, id }: { children: ReactNode; id?: string }) {
  return (
    <span id={id} style={visuallyHiddenStyle}>
      {children}
    </span>
  );
}

/** Mount once at the app root. Renders one polite and one assertive status region. */
export function LiveRegion() {
  const snap = useSyncExternalStore(subscribeAnnouncer, getAnnouncerSnapshot, getAnnouncerSnapshot);
  return (
    <>
      <div
        data-testid="live-polite"
        role="status"
        aria-live="polite"
        aria-atomic="true"
        style={visuallyHiddenStyle}
      >
        {snap.polite}
      </div>
      <div
        data-testid="live-assertive"
        role="alert"
        aria-live="assertive"
        aria-atomic="true"
        style={visuallyHiddenStyle}
      >
        {snap.assertive}
      </div>
    </>
  );
}

/** First focusable element: visible on focus; moves focus to `#target` (made tabindex=-1) on activation. */
export function SkipLink({
  target = "main",
  children = "본문으로 건너뛰기",
}: {
  target?: string;
  children?: ReactNode;
}) {
  const [focused, setFocused] = useState(false);
  const style: CSSProperties = focused
    ? {
        position: "fixed",
        top: 8,
        left: 8,
        zIndex: 1000,
        padding: "8px 12px",
        background: "var(--accent)",
        color: "var(--on-accent)",
        borderRadius: 4,
      }
    : visuallyHiddenStyle;
  return (
    <a
      className="skip-link"
      href={`#${target}`}
      style={style}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      onClick={(event) => {
        // Hash routing owns location.hash; never let the anchor navigate.
        event.preventDefault();
        const el = document.getElementById(target);
        if (!el) return;
        if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "-1");
        el.focus();
        el.scrollIntoView?.({ block: "start" });
      }}
    >
      {children}
    </a>
  );
}

/**
 * "Disabled WITH reason": when `reason` is non-empty the child stays focusable,
 * gets aria-disabled + aria-describedby, and its click is swallowed. The
 * description element is `hidden` (still a valid aria-describedby target, but
 * not part of the page text or reading order); the visible tooltip is mounted
 * only while the control is hovered or focused. Without a reason the child is
 * returned untouched.
 */
export function DisabledReason({
  reason,
  children,
  tooltip = true,
}: {
  reason?: string | null;
  children: ReactElement<Record<string, unknown>>;
  /**
   * false: the caller prints the reason as visible text next to the control (CommandButton
   * `showReason`), so no hover/focus box repeats it.
   */
  tooltip?: boolean;
}) {
  const descriptionId = useId();
  const [shown, setShown] = useState(false);
  if (!reason) return children;
  const existing = children.props["aria-describedby"];
  const describedBy =
    typeof existing === "string" && existing ? `${existing} ${descriptionId}` : descriptionId;
  const guarded = cloneElement(children, {
    "aria-disabled": true,
    "aria-describedby": describedBy,
    "data-disabled-reason": reason,
    onClick: (event: MouseEvent) => {
      event.preventDefault();
      event.stopPropagation();
    },
  });
  return (
    // biome-ignore lint/a11y/noStaticElementInteractions: wrapper only mirrors hover/focus of the focusable child to show the tooltip
    <span
      className="disabled-reason"
      style={{ position: "relative", display: "inline-flex" }}
      onMouseEnter={() => setShown(true)}
      onMouseLeave={() => setShown(false)}
      onFocus={() => setShown(true)}
      onBlur={() => setShown(false)}
      onKeyDown={(event) => {
        if (event.key === "Escape") setShown(false);
      }}
    >
      {guarded}
      <span id={descriptionId} hidden>
        {reason}
      </span>
      {shown && tooltip ? (
        // aria-hidden: the same sentence is already the control's description.
        <span
          role="tooltip"
          aria-hidden="true"
          data-shown="true"
          style={{
            position: "absolute",
            top: "100%",
            left: 0,
            marginTop: 4,
            zIndex: 900,
            padding: "4px 8px",
            background: "var(--bg-raised)",
            color: "var(--text)",
            border: "1px solid var(--line)",
            borderRadius: 4,
            fontSize: "var(--fs-table-aux)",
            whiteSpace: "nowrap",
          }}
        >
          {reason}
        </span>
      ) : null}
    </span>
  );
}
