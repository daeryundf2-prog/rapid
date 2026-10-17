/**
 * Main-window side of the viewer window (U-F2): opens / focuses / closes the popup, mirrors the
 * viewer state to it, hands it the auth token by `postMessage`, and runs what the popout asks
 * (history, mode, review marks on the same row, cache refresh after a toolbar mark).
 *
 * While the popout is open the wide viewer pane shows the "창으로 보는 중 · 되돌리기" rail
 * (Layout reads `usePopoutHost`). Closing the popout (its × or 되돌리기) brings the pane back.
 */

import type { QueryClient } from "@tanstack/react-query";
import { create } from "zustand";
import { announce } from "../../../a11y";
import { authToken } from "../../../api/client";
import { runCommand } from "../../../commands/registry";
import { type Command, KEY_MAP } from "../../../contracts/command";
import { encodeRowRef } from "../../../contracts/rowRef";
import { NO_VIEWER_REASON, parseHash, stageHasViewer, stageOf } from "../../../router";
import { useAppStore } from "../../../state/store";
import { currentTimezone } from "../../grid/columns/common";
import {
  type ChannelLike,
  cloneable,
  createChannel,
  fromHost,
  isPopoutToMain,
  NO_CHANNEL_REASON,
  newHostId,
  POPOUT_WINDOW_NAME,
  POPUP_BLOCKED_REASON,
  type PopoutState,
  type PopoutToMain,
  popoutUrl,
  readBounds,
  TOKEN_MESSAGE,
  windowFeatures,
} from "./protocol";

export const POPOUT_COMMAND_ID = "viewer.popout";
export const POPOUT_RETURN_COMMAND_ID = "viewer.popout.return";
export const NOT_POPPED_REASON = "뷰어가 새 창에 열려 있지 않습니다";
export const DRAWER_REASON =
  "좁은 화면(1200px 미만)에서는 뷰어가 서랍으로 열립니다 — 창을 넓히면 뷰어를 새 창으로 열 수 있습니다";
/** The popup's `closed` flag is polled as a backstop for a crashed / killed popout. */
const CLOSED_POLL_MS = 1000;

export type PopoutStatus = "closed" | "open";

interface PopoutHostState {
  status: PopoutStatus;
  /** The last open attempt was blocked by the browser (shown as the command's note). */
  blocked: boolean;
}

export const usePopoutHost = create<PopoutHostState>(() => ({ status: "closed", blocked: false }));

let popup: Window | null = null;
let channel: ChannelLike | null = null;
let pollTimer: ReturnType<typeof setInterval> | null = null;
let offStore: (() => void) | null = null;
let queryClient: QueryClient | null = null;
let lastSentKey = "";
/** This page load's host id (see protocol HOST_PARAM). */
const HOST_ID = newHostId();
/** A `closed` from the window waits this long: a reload of the window is not a close. */
const CLOSED_GRACE_MS = 1500;
let closedTimer: ReturnType<typeof setTimeout> | null = null;

export function popoutHostId(): string {
  return HOST_ID;
}

function stateMessage(): PopoutState {
  const s = useAppStore.getState();
  return {
    type: "state",
    target: s.viewerTarget,
    row: s.viewerRow,
    ...(s.route.row && s.route.mode ? { mode: s.route.mode } : {}),
    tz: currentTimezone(),
    theme: s.theme,
    ...(s.route.q ? { q: s.route.q } : {}),
    runId: s.route.runId,
  };
}

function stateKey(message: PopoutState): string {
  return JSON.stringify([
    message.target ? encodeRowRef(message.target.ref) : "",
    message.target?.sourcePath ?? "",
    message.target?.runId ?? "",
    message.row ? encodeRowRef(message.row.ref) : "",
    message.row?.fields.reviewStatus ?? "",
    message.row?.fields.tags ?? "",
    message.mode ?? "",
    message.tz,
    message.theme,
    message.q ?? "",
    message.runId,
  ]);
}

/** Send the viewer state (deduplicated unless forced). */
export function sendState(force = false): void {
  if (!channel || usePopoutHost.getState().status !== "open") return;
  const message = stateMessage();
  const key = stateKey(message);
  if (!force && key === lastSentKey) return;
  lastSentKey = key;
  try {
    channel.postMessage({ ...cloneable(message), host: HOST_ID });
  } catch {
    // A closed channel: the closed-poll brings the pane back.
  }
}

function sendToken(): void {
  const token = authToken();
  if (!popup || popup.closed || !token) return;
  // Only the window we opened, only our origin: the token never touches the channel or a URL.
  popup.postMessage({ type: TOKEN_MESSAGE, token }, window.location.origin);
}

function stopWatching(): void {
  if (closedTimer) clearTimeout(closedTimer);
  closedTimer = null;
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
  offStore?.();
  offStore = null;
  channel?.close();
  channel = null;
}

/** The popout went away (closed, 되돌리기): the pane comes back where it was. */
function markClosed(announceIt = true): void {
  if (usePopoutHost.getState().status === "closed") return;
  stopWatching();
  popup = null;
  lastSentKey = "";
  usePopoutHost.setState({ status: "closed" });
  if (announceIt) announce("뷰어 창이 닫혀 뷰어를 메인 창으로 되돌렸습니다.");
}

function onMessage(data: unknown): void {
  if (!fromHost(data, HOST_ID) || !isPopoutToMain(data)) return;
  const message: PopoutToMain = data;
  const app = useAppStore.getState();
  switch (message.type) {
    case "hello":
      // A reloaded window says hello again: it stays open.
      if (closedTimer) clearTimeout(closedTimer);
      closedTimer = null;
      sendToken();
      sendState(true);
      return;
    case "history": {
      const current = app.viewerTarget;
      const same =
        (current === null && message.target === null) ||
        (current !== null &&
          message.target !== null &&
          encodeRowRef(current.ref) === encodeRowRef(message.target.ref) &&
          current.runId === message.target.runId);
      if (!same) app.setViewerTarget(message.target, { row: message.row });
      return;
    }
    case "mode":
      if (app.route.row && app.route.mode !== message.mode) app.setViewerMode(message.mode);
      return;
    case "command":
      void runCommand(message.id);
      return;
    case "invalidate":
      void queryClient?.invalidateQueries({ predicate: (query) => query.queryKey.includes(message.runId) });
      return;
    case "navigate": {
      // Only a route of the case this window shows (a link can never switch cases behind the analyst).
      const route = parseHash(message.hash);
      if (!route.runId || route.runId !== app.route.runId) return;
      app.navigate(route);
      window.focus();
      return;
    }
    case "return":
      markClosed(false);
      announce("뷰어를 메인 창으로 되돌렸습니다.");
      return;
    case "closed":
      // The window unloads: closed, or reloading (then it says hello again within the grace).
      if (closedTimer) clearTimeout(closedTimer);
      closedTimer = setTimeout(() => {
        closedTimer = null;
        if (!popup || popup.closed) markClosed();
      }, CLOSED_GRACE_MS);
      return;
    default:
  }
}

function startWatching(): boolean {
  channel = createChannel();
  if (!channel) return false;
  channel.onmessage = (event) => onMessage(event.data);
  offStore = useAppStore.subscribe((state, prev) => {
    if (
      state.viewerTarget !== prev.viewerTarget ||
      state.viewerRow !== prev.viewerRow ||
      state.route !== prev.route ||
      state.theme !== prev.theme ||
      state.timezone !== prev.timezone
    ) {
      sendState();
    }
  });
  pollTimer = setInterval(() => {
    if (!popup || popup.closed) markClosed();
  }, CLOSED_POLL_MS);
  return true;
}

export type OpenResult = "opened" | "focused" | "blocked" | "unsupported";

/** Ctrl+Shift+V: open the viewer window (or bring the open one to the front). */
export function openViewerPopout(): OpenResult {
  if (usePopoutHost.getState().status === "open" && popup && !popup.closed) {
    popup.focus();
    return "focused";
  }
  // Closed a moment ago and the poll has not noticed yet: tidy up before opening again.
  if (usePopoutHost.getState().status === "open") markClosed(false);
  if (typeof BroadcastChannel === "undefined" && !createChannel()) return "unsupported";
  const opened = window.open(
    popoutUrl(window.location, HOST_ID),
    // One window per console tab: a fixed name would let tab B take over tab A's window.
    `${POPOUT_WINDOW_NAME}-${HOST_ID}`,
    windowFeatures(readBounds(), window.screen?.availWidth),
  );
  if (!opened) {
    usePopoutHost.setState({ blocked: true });
    useAppStore.getState().showNotice(POPUP_BLOCKED_REASON, "error");
    announce(POPUP_BLOCKED_REASON, { politeness: "assertive" });
    return "blocked";
  }
  popup = opened;
  if (!startWatching()) {
    opened.close();
    popup = null;
    return "unsupported";
  }
  usePopoutHost.setState({ status: "open", blocked: false });
  announce("뷰어를 새 창으로 열었습니다. 메인 창의 뷰어 열은 접혔습니다.");
  return "opened";
}

/** 되돌리기: close the viewer window and show the viewer pane again. */
export function returnViewerFromPopout(): void {
  const target = popup;
  markClosed(false);
  try {
    target?.close();
  } catch {
    // Already gone.
  }
  announce("뷰어를 메인 창으로 되돌렸습니다.");
}

/** Focus the open viewer window (Enter on a row while the viewer lives there). */
export function focusPopout(): boolean {
  if (usePopoutHost.getState().status !== "open" || !popup || popup.closed) return false;
  popup.focus();
  return true;
}

/**
 * Mounted once by the main app: lets the popout refresh the grid's review data, and closes the
 * popout when this window unloads (reload / tab close).
 */
export function installPopoutHost(client: QueryClient): () => void {
  queryClient = client;
  const onUnload = () => {
    if (usePopoutHost.getState().status !== "open") return;
    try {
      channel?.postMessage({ type: "main-closed", host: HOST_ID });
      popup?.close();
    } catch {
      // Best effort.
    }
  };
  window.addEventListener("beforeunload", onUnload);
  window.addEventListener("pagehide", onUnload);
  return () => {
    window.removeEventListener("beforeunload", onUnload);
    window.removeEventListener("pagehide", onUnload);
    queryClient = null;
  };
}

function popoutReason(): string | undefined {
  const state = useAppStore.getState();
  if (!stageHasViewer(stageOf(state.route))) return NO_VIEWER_REASON;
  if (state.viewerIsDrawer && usePopoutHost.getState().status !== "open") return DRAWER_REASON;
  if (typeof BroadcastChannel === "undefined") return NO_CHANNEL_REASON;
  return undefined;
}

export function popoutCommands(): Command[] {
  return [
    {
      id: POPOUT_COMMAND_ID,
      label: "뷰어를 새 창으로 (듀얼 모니터)",
      group: "viewer",
      shortcut: KEY_MAP.viewerPopout,
      icon: "external",
      disabledReason: popoutReason,
      run: () => {
        openViewerPopout();
      },
    },
    {
      id: POPOUT_RETURN_COMMAND_ID,
      label: "뷰어 창 닫고 메인 창으로 되돌리기",
      group: "viewer",
      icon: "panel-right",
      disabledReason: () => (usePopoutHost.getState().status === "open" ? undefined : NOT_POPPED_REASON),
      run: () => returnViewerFromPopout(),
    },
  ];
}

/** Tests only. */
export function resetPopoutHost(): void {
  stopWatching();
  popup = null;
  lastSentKey = "";
  usePopoutHost.setState({ status: "closed", blocked: false });
}
