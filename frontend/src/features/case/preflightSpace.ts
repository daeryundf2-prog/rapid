// T-186 / review WB-10/11 P1-3: the disk free-space advice the server attaches to every run start
// (`POST /api/runs`, `POST /api/cases/{id}/runs`, `POST /api/runs/{id}/retry` → `preflight_space`,
// `rapidtriage/api/app/preflight_space.py`). The server never refuses a run for space; the console
// shows the advice as a non-blocking toast so a run onto a disk that is too small does not start
// silently.

import { announce } from "../../a11y";
import type { PreflightSpace } from "../../api/runs";
import { type ToastTone, useToastStore } from "../../components/toastStore";

const LEVEL_TEXT: Record<string, { label: string; tone: ToastTone }> = {
  block: { label: "디스크 여유 부족(추정)", tone: "error" },
  warn: { label: "디스크 여유 주의(추정)", tone: "warn" },
  unknown: { label: "디스크 여유 확인 못 함", tone: "warn" },
};

export interface PreflightSpaceNotice {
  text: string;
  tone: ToastTone;
}

/**
 * The Korean notice for a run start's `preflight_space`: `warn` and `block` always, `unknown` only
 * when the server named a code (an estimate it could not complete, not a dry run); null for `ok`,
 * no check, or a body without a message.
 */
export function preflightSpaceNotice(space: PreflightSpace | null | undefined): PreflightSpaceNotice | null {
  if (!space || typeof space !== "object") return null;
  const level = String(space.level ?? "");
  const message = typeof space.message === "string" ? space.message.trim() : "";
  if (!message) return null;
  if (level === "unknown" && !space.code) return null;
  const entry = LEVEL_TEXT[level];
  if (!entry) return null;
  return { text: `${entry.label} — 처리는 시작됨: ${message}`, tone: entry.tone };
}

/** Toast (and announce) the advice of a run-start response; nothing for `ok` / no check. */
export function showPreflightSpace(
  response: { preflight_space?: PreflightSpace | null } | null | undefined,
): void {
  const notice = preflightSpaceNotice(response?.preflight_space);
  if (!notice) return;
  useToastStore.getState().push(notice.text, notice.tone);
  announce(notice.text);
}
