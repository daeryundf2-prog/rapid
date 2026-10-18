/**
 * 뷰어 창 모드 (viewer-families U-F2): the viewer runs as a second instance of the same bundle in
 * its own browser window (`?popout=viewer`) and follows the main window over a BroadcastChannel.
 *
 *   main → popout: `state` (viewer target / grid row / mode / timezone / theme / highlight terms),
 *                  `main-closed` (the main window is going away: the popout closes itself)
 *   popout → main: `hello` (ready; asks for the token and the state), `history` (Alt+←/→ inside the
 *                  popout), `mode` (tab choice), `command` (R/X/I/B → the main window's review
 *                  command on the same row), `invalidate` (a toolbar mark changed the run's review
 *                  data), `return` (되돌리기), `closed`
 *
 * The auth token never rides in the URL and never on the channel (every same-origin tab can listen
 * there): the main window posts it with `window.postMessage` to the popup it opened, pinned to its
 * own origin, and the popout accepts it only from `window.opener`; it is kept in sessionStorage.
 */

import type { GridRow } from "../../../contracts/collection";
import type { ViewerMode, ViewerTarget } from "../../../contracts/viewer";
import { readStoredJson, writeStored } from "../../../state/storage";

export const POPOUT_CHANNEL = "rapidforensic.viewer";
export const POPOUT_WINDOW_NAME = "rapidforensic-viewer";
export const POPOUT_PARAM = "popout";
export const POPOUT_VALUE = "viewer";
/**
 * The main window that opened the viewer window (random per page load, not a secret): every channel
 * message carries it, so two console tabs with their own viewer windows never steer each other.
 */
export const HOST_PARAM = "host";
export const POPOUT_BOUNDS_KEY = "rapidtriage.v2.popout.bounds";
/** `window.postMessage` type of the token hand-off (main → its popup only). */
export const TOKEN_MESSAGE = "rapidforensic.viewer.token";

export const POPUP_BLOCKED_REASON =
  "브라우저가 팝업을 차단했습니다 — 주소창의 팝업 차단 아이콘에서 이 사이트를 허용한 뒤 다시 시도하세요 (Ctrl+Shift+V)";
export const NO_CHANNEL_REASON =
  "이 브라우저는 창 간 통신(BroadcastChannel)을 지원하지 않아 뷰어 창을 열 수 없습니다";

/** Review commands a popout may ask the main window to run (R / X / I / B on the same row). */
export const FORWARDED_COMMANDS: ReadonlySet<string> = new Set([
  "review.mark.relevant",
  "review.mark.excluded",
  "review.mark.needs-review",
  "review.mark.bookmark",
  "review.mark.include-in-report",
  // "같은 출처의 다른 행" from the window's toolbar: the main grid filters.
  "navigate.rows-for-source",
]);

export interface PopoutState {
  type: "state";
  target: ViewerTarget | null;
  row: GridRow | null;
  mode?: ViewerMode;
  /** Resolved display timezone ("local" | "utc" | IANA). */
  tz: string;
  theme: "dark" | "light" | null;
  /** Route `q=` (document / source highlight). */
  q?: string;
  runId: string | null;
}

export type MainToPopout = PopoutState | { type: "main-closed" };

export interface WindowBounds {
  left: number;
  top: number;
  width: number;
  height: number;
}

export type PopoutToMain =
  | { type: "hello" }
  | { type: "history"; target: ViewerTarget | null; row: GridRow | null }
  | { type: "mode"; mode: ViewerMode | undefined }
  | { type: "command"; id: string }
  | { type: "invalidate"; runId: string }
  /** A route link clicked inside the window (`#/case/…`): the main window opens it. */
  | { type: "navigate"; hash: string }
  | { type: "return" }
  | { type: "closed" };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTarget(value: unknown): value is ViewerTarget | null {
  return (
    value === null ||
    (isRecord(value) && typeof value.runId === "string" && isRecord(value.ref) && "sourcePath" in value)
  );
}

export function isMainToPopout(value: unknown): value is MainToPopout {
  if (!isRecord(value)) return false;
  if (value.type === "main-closed") return true;
  return value.type === "state" && isTarget(value.target) && typeof value.tz === "string";
}

export function isPopoutToMain(value: unknown): value is PopoutToMain {
  if (!isRecord(value) || typeof value.type !== "string") return false;
  switch (value.type) {
    case "hello":
    case "return":
    case "closed":
      return true;
    case "history":
      return isTarget(value.target);
    case "mode":
      return value.mode === undefined || typeof value.mode === "string";
    case "command":
      return typeof value.id === "string" && FORWARDED_COMMANDS.has(value.id);
    case "invalidate":
      return typeof value.runId === "string";
    case "navigate":
      return isRouteHash(value.hash);
    default:
      return false;
  }
}

/** A console route fragment (`#/case/…`, bounded length) — the only thing `navigate` may carry. */
export function isRouteHash(value: unknown): value is string {
  return typeof value === "string" && value.startsWith("#/") && value.length <= 4096;
}

/** This document is the viewer window (`?popout=viewer`). */
export function isPopoutWindow(
  search: string = typeof window === "undefined" ? "" : window.location.search,
): boolean {
  return new URLSearchParams(search).get(POPOUT_PARAM) === POPOUT_VALUE;
}

/** The viewer window's URL: same origin and bundle path, no hash (no token, no route). */
export function popoutUrl(loc: Pick<Location, "origin" | "pathname"> = window.location, host = ""): string {
  const hostPart = host ? `&${HOST_PARAM}=${encodeURIComponent(host)}` : "";
  return `${loc.origin}${loc.pathname}?${POPOUT_PARAM}=${POPOUT_VALUE}${hostPart}`;
}

/** The opener's host id of this viewer window ("" when absent). */
export function hostIdFromSearch(
  search: string = typeof window === "undefined" ? "" : window.location.search,
): string {
  return new URLSearchParams(search).get(HOST_PARAM) ?? "";
}

export function newHostId(): string {
  const bytes = new Uint8Array(8);
  globalThis.crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** A channel message of `host` (anything else on the channel is someone else's). */
export function fromHost(data: unknown, host: string): boolean {
  return isRecord(data) && data.host === host;
}

function isBounds(value: unknown): value is WindowBounds {
  return (
    isRecord(value) &&
    ["left", "top", "width", "height"].every(
      (key) => typeof value[key] === "number" && Number.isFinite(value[key]),
    )
  );
}

export function readBounds(): WindowBounds | null {
  const bounds = readStoredJson(POPOUT_BOUNDS_KEY, isBounds);
  return bounds && bounds.width >= 320 && bounds.height >= 240 ? bounds : null;
}

export function writeBounds(bounds: WindowBounds): void {
  if (bounds.width < 320 || bounds.height < 240) return;
  writeStored(POPOUT_BOUNDS_KEY, JSON.stringify(bounds));
}

/** `window.open` features: the remembered bounds, else 900×900 at the right of the screen. */
export function windowFeatures(bounds: WindowBounds | null, screenWidth = 1920): string {
  const b = bounds ?? { width: 900, height: 900, left: Math.max(0, screenWidth - 940), top: 40 };
  return `popup,width=${Math.round(b.width)},height=${Math.round(b.height)},left=${Math.round(b.left)},top=${Math.round(b.top)}`;
}

/** Structured-clone-safe copy (grid rows may carry non-cloneable values such as functions). */
export function cloneable<T>(value: T): T {
  try {
    return structuredClone(value);
  } catch {
    return JSON.parse(JSON.stringify(value ?? null)) as T;
  }
}

/** Channel factory (tests inject a fake). */
export type ChannelLike = Pick<BroadcastChannel, "postMessage" | "close"> & {
  onmessage: ((event: MessageEvent) => void) | null;
};

export let createChannel = (): ChannelLike | null =>
  typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel(POPOUT_CHANNEL);

/** Tests only. */
export function setChannelFactory(factory: () => ChannelLike | null): void {
  createChannel = factory;
}
