/**
 * Leave guards (r8 T-144): a screen with unsaved input registers a guard; before the route moves
 * (in-app navigation, back/forward, a hand-edited hash) every guard is asked whether the move
 * leaves it, and if one answers with a sentence the analyst confirms first. Closing or reloading
 * the tab is covered by the guard's own `beforeunload` listener (see `useLeaveGuard` callers).
 */

import type { Route } from "../router";

/** The question asked before leaving a screen with unsaved input. */
export const UNSAVED_LEAVE_MESSAGE =
  "저장하지 않은 내용이 있습니다. 이 화면을 떠나면 입력한 내용이 사라집니다. 떠날까요?";

/** Returns the confirmation sentence when moving `prev → next` would drop unsaved input, else null. */
export type LeaveGuard = (prev: Route, next: Route) => string | null;

const guards = new Set<LeaveGuard>();

/** Register a guard; returns its unregister function. */
export function registerLeaveGuard(guard: LeaveGuard): () => void {
  guards.add(guard);
  return () => {
    guards.delete(guard);
  };
}

/** The first guard's sentence for `prev → next`, or null when nothing would be lost. */
export function leaveMessage(prev: Route, next: Route): string | null {
  for (const guard of guards) {
    const message = guard(prev, next);
    if (message) return message;
  }
  return null;
}

/** True when the move may go ahead (no guard objects, or the analyst confirmed). */
export function allowLeave(prev: Route, next: Route): boolean {
  const message = leaveMessage(prev, next);
  if (!message) return true;
  if (typeof window === "undefined" || typeof window.confirm !== "function") return true;
  try {
    return window.confirm(message) === true;
  } catch {
    return true;
  }
}
