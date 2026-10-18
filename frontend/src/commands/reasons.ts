/** Shared Korean disabled reasons. */
export const NO_RUN_REASON = "케이스를 먼저 선택하세요";

/** Confirmation sentence of 모두 취소 (irreversible: every remaining task stops). */
export const CANCEL_ALL_CONFIRM = "남은 처리를 모두 취소할까요? 취소한 태스크는 되돌릴 수 없습니다";

/** Ask before an irreversible action (native dialog: focus-safe, screen-reader friendly). */
export function confirmAction(message: string): boolean {
  if (typeof window === "undefined" || typeof window.confirm !== "function") return true;
  try {
    return window.confirm(message);
  } catch {
    return true;
  }
}
