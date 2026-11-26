/**
 * Loading / empty / error cards shared by the explorer views (plan X18):
 * a loading card (the wait panel: label + elapsed seconds) with an optional 취소 action and
 * descriptive empty states.
 */

import type { ReactNode } from "react";
import { WaitPanel } from "../../components/WaitPanel";

export function LoadingCard({ label, onCancel }: { label: string; onCancel?: () => void }) {
  return (
    <WaitPanel className="view-state" label={label}>
      {onCancel ? (
        <button type="button" className="view-link" onClick={onCancel}>
          취소
        </button>
      ) : null}
    </WaitPanel>
  );
}

export function EmptyState({
  title,
  hint,
  children,
}: {
  title: string;
  hint?: string;
  children?: ReactNode;
}) {
  return (
    <div className="view-state" role="status">
      <p className="view-state-title">{title}</p>
      {hint ? <p className="view-state-hint">{hint}</p> : null}
      {children}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="view-state view-state-error" role="alert">
      <p className="view-state-title">{message}</p>
      {onRetry ? (
        <button type="button" className="view-link" onClick={onRetry}>
          다시 불러오기
        </button>
      ) : null}
    </div>
  );
}
