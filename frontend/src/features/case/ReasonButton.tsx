import { type ButtonHTMLAttributes, useId } from "react";

/**
 * Button that stays focusable but inert while `reason` is set (U3): the reason
 * is exposed as a tooltip and via aria-describedby; click does nothing.
 */
export function ReasonButton({
  reason,
  onClick,
  children,
  className = "button",
  ...rest
}: { reason?: string } & ButtonHTMLAttributes<HTMLButtonElement>) {
  const id = useId();
  return (
    <>
      <button
        {...rest}
        type={rest.type ?? "button"}
        className={className}
        aria-disabled={reason ? true : undefined}
        aria-describedby={reason ? id : undefined}
        title={reason}
        onClick={(event) => {
          if (reason) {
            event.preventDefault();
            return;
          }
          onClick?.(event);
        }}
      >
        {children}
      </button>
      {reason && (
        <span id={id} className="case-reason" data-testid="disabled-reason">
          {reason}
        </span>
      )}
    </>
  );
}
