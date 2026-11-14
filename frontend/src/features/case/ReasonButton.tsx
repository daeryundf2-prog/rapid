import { type ButtonHTMLAttributes, type Ref, useId, useState } from "react";

/**
 * Button that stays focusable but inert while `reason` is set (U3): the reason
 * is exposed as a tooltip and via aria-describedby; click does nothing.
 *
 * `quietReason` (r7 L4, C-L4): the reason text is not printed next to the button the moment a
 * dialog opens ("…입력하세요." before the analyst typed anything) — it stays in the accessibility
 * tree (aria-describedby) and appears on hover / keyboard focus, and for good after a click on the
 * inert button.
 */
export function ReasonButton({
  reason,
  onClick,
  children,
  className = "button",
  quietReason = false,
  ref,
  ...rest
}: {
  reason?: string;
  quietReason?: boolean;
  ref?: Ref<HTMLButtonElement>;
} & ButtonHTMLAttributes<HTMLButtonElement>) {
  const id = useId();
  const [pointed, setPointed] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const shown = !quietReason || pointed || attempted;
  return (
    <>
      <button
        {...rest}
        ref={ref}
        type={rest.type ?? "button"}
        className={className}
        aria-disabled={reason ? true : undefined}
        aria-describedby={reason ? id : undefined}
        title={reason}
        onMouseEnter={(event) => {
          setPointed(true);
          rest.onMouseEnter?.(event);
        }}
        onMouseLeave={(event) => {
          setPointed(false);
          rest.onMouseLeave?.(event);
        }}
        onFocus={(event) => {
          setPointed(true);
          rest.onFocus?.(event);
        }}
        onBlur={(event) => {
          setPointed(false);
          rest.onBlur?.(event);
        }}
        onClick={(event) => {
          if (reason) {
            event.preventDefault();
            setAttempted(true);
            return;
          }
          onClick?.(event);
        }}
      >
        {children}
      </button>
      {reason && (
        <span
          id={id}
          className={shown ? "case-reason" : "case-reason visually-hidden"}
          data-testid="disabled-reason"
          data-quiet={shown ? undefined : ""}
        >
          {reason}
        </span>
      )}
    </>
  );
}
