/**
 * Status chips for job / run / file states (review #11, #24): one `.status-chip` (dot + text)
 * everywhere a table or card shows a state, its dot colour chosen by the state — ok (done),
 * danger (failed / missing), warn (cancelled / partial), info (queued / running), neutral (not
 * run yet). Review statuses keep their own <StatusChip> (X3 colours).
 */

export type ChipTone = "ok" | "danger" | "warn" | "info" | "";

const TONES: Record<string, ChipTone> = {
  completed: "ok",
  complete: "ok",
  succeeded: "ok",
  success: "ok",
  done: "ok",
  ok: "ok",
  exists: "ok",
  failed: "danger",
  error: "danger",
  missing: "danger",
  cancelled: "warn",
  canceled: "warn",
  partial: "warn",
  completed_with_errors: "warn",
  warning: "warn",
  queued: "info",
  running: "info",
};

/** Dot tone of a state string ("" = neutral, e.g. 미실행 / unknown). */
export function chipToneOf(status: string | null | undefined): ChipTone {
  if (!status) return "";
  return TONES[status.toLowerCase()] ?? "";
}

export function ToneChip({
  tone,
  children,
  title,
  testId,
}: {
  tone: ChipTone;
  children: string;
  title?: string;
  testId?: string;
}) {
  return (
    <span
      className={`status-chip tone-chip${tone ? ` ${tone}` : ""}`}
      data-tone={tone || undefined}
      title={title}
      data-testid={testId}
    >
      {children}
    </span>
  );
}
