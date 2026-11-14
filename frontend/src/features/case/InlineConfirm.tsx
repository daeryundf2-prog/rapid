import { type ReactNode, useEffect, useRef } from "react";
import { ReasonButton } from "./ReasonButton";
import "./case.css";

/**
 * Inline confirmation of a destructive action inside a list or dialog (T-034, IS-094): the message
 * says exactly what happens, focus starts on 취소 so Enter on an unread confirmation never deletes,
 * Esc cancels (this confirmation only, not the dialog around it), and only an explicit click on the
 * danger-styled button confirms. Remount it (`key`) to re-focus 취소 for another target.
 */
export function InlineConfirm({
  label,
  testId,
  className,
  confirmLabel = "삭제",
  busy = false,
  onCancel,
  onConfirm,
  children,
}: {
  /** Accessible name of the group ("태그 삭제 확인"). */
  label: string;
  /** Group testid; the buttons get `${testId}-cancel` / `${testId}-ok`. */
  testId: string;
  className?: string;
  confirmLabel?: string;
  busy?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  children: ReactNode;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    cancelRef.current?.focus();
  }, []);
  return (
    <fieldset
      className={className}
      data-testid={testId}
      onKeyDown={(event) => {
        if (event.key !== "Escape") return;
        event.stopPropagation();
        onCancel();
      }}
    >
      <legend className="sr-only">{label}</legend>
      {children}
      <div className="case-actions">
        <button
          ref={cancelRef}
          type="button"
          className="button"
          data-testid={`${testId}-cancel`}
          onClick={onCancel}
        >
          취소
        </button>
        <ReasonButton
          className="button danger"
          data-testid={`${testId}-ok`}
          reason={busy ? "처리하는 중입니다" : undefined}
          onClick={onConfirm}
        >
          {confirmLabel}
        </ReasonButton>
      </div>
    </fieldset>
  );
}
