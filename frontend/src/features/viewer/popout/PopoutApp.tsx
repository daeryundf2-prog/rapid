/**
 * The viewer window (U-F2, `?popout=viewer`): the same Viewer (mode tabs · toolbar · banners ·
 * 메타) filling its own browser window, following the main window over the channel.
 *
 * Keys inside the window: Alt+←/→ (the viewer's history, mirrored to the main window), 1–8 (mode
 * tabs), R/X/I/B (run by the main window on the same row, so its grid chips update). J/K stay in the
 * main window's grid.
 */

import { useEffect, useRef, useState } from "react";
import { announce, LiveRegion } from "../../../a11y";
import { authToken, setAuthToken } from "../../../api/client";
import { viewerTargetKey as viewerTargetKeyOf } from "../../../app/viewerBridge";
import { registerCommands } from "../../../commands/registry";
import { ToastRegion } from "../../../components/ToastRegion";
import type { GridRow } from "../../../contracts/collection";
import { type Command, KEY_MAP } from "../../../contracts/command";
import type { ViewerMode, ViewerTarget } from "../../../contracts/viewer";
import { Icon } from "../../../icons";
import { EMPTY_ROUTE } from "../../../router";
import { useShortcuts } from "../../../shortcuts";
import { applyThemeAttribute } from "../../../state/slices/prefs";
import { useAppStore } from "../../../state/store";
import { useFamilyCatalogLoader } from "../../flags/catalog";
import {
  getViewerRouteMode,
  getViewerTarget,
  setViewerRouteMode,
  setViewerTarget,
  subscribeViewerAdapter,
} from "../adapter";
import { tabId } from "../ModeTabs";
import { MODE_LABELS, MODE_ORDER } from "../modes";
import { targetTitle, Viewer } from "../Viewer";
import {
  type ChannelLike,
  cloneable,
  createChannel,
  fromHost,
  hostIdFromSearch,
  isMainToPopout,
  isRouteHash,
  type PopoutState,
  type PopoutToMain,
  TOKEN_MESSAGE,
  writeBounds,
} from "./protocol";
import "./popout.css";

/** How long the window waits for the token before showing state anyway (sessionStorage copy). */
const TOKEN_WAIT_MS = 1500;
const BOUNDS_SAVE_MS = 400;

/** Window title: the grid row's own title (one line, ≤80 chars), else the viewer's heading. */
export function popoutTitle(target: ViewerTarget | null, row: GridRow | null): string {
  if (!target) return "원본 뷰어";
  const own = row && row.ref.locator === target.ref.locator ? row.title.replace(/\s+/g, " ").trim() : "";
  const text = own || targetTitle(target, null, row);
  return text.length > 80 ? `${text.slice(0, 79)}…` : text;
}

export type PopoutPhase = "connecting" | "ready" | "orphan";

const MARK_KEYS: ReadonlyArray<{ id: string; shortcut: string; label: string }> = [
  { id: "review.mark.relevant", shortcut: KEY_MAP.markRelevant, label: "관련 있음 표시" },
  { id: "review.mark.excluded", shortcut: KEY_MAP.markExcluded, label: "제외 표시" },
  { id: "review.mark.needs-review", shortcut: KEY_MAP.markNeedsReview, label: "재검토 표시" },
  { id: "review.mark.bookmark", shortcut: KEY_MAP.bookmark, label: "북마크" },
];

function windowBounds() {
  return {
    left: window.screenX,
    top: window.screenY,
    width: window.outerWidth || window.innerWidth,
    height: window.outerHeight || window.innerHeight,
  };
}

/** Select a mode tab as a click would (disabled tabs announce their reason). */
function selectModeTab(mode: ViewerMode): void {
  const tab = document.getElementById(tabId(mode));
  if (!tab) {
    announce(`${MODE_LABELS[mode]} 모드는 이 행에 없습니다.`);
    return;
  }
  tab.click();
  tab.focus();
}

export function PopoutApp() {
  const [phase, setPhase] = useState<PopoutPhase>(() =>
    typeof window !== "undefined" && window.opener ? "connecting" : "orphan",
  );
  const [title, setTitle] = useState("원본 뷰어");
  // The row the window shows (its locator — no evidence content): tests and QA tools read it.
  const [locator, setLocator] = useState("");
  const channelRef = useRef<ChannelLike | null>(null);
  // The main window this one belongs to (URL `host=`): messages of other console tabs are ignored.
  const hostRef = useRef(hostIdFromSearch());
  useShortcuts();
  // The server catalogue (rules added after this bundle): loaded once the token is in.
  useFamilyCatalogLoader(phase === "ready");

  const post = (message: PopoutToMain) => {
    try {
      channelRef.current?.postMessage({ ...cloneable(message), host: hostRef.current });
    } catch {
      // Channel gone: the main window's closed-poll recovers.
    }
  };

  // Channel, token hand-off, state application and the echo guard.
  // biome-ignore lint/correctness/useExhaustiveDependencies: mount-only wiring
  useEffect(() => {
    if (phase === "orphan") return;
    const channel = createChannel();
    channelRef.current = channel;
    let tokenReady = Boolean(authToken());
    let pending: PopoutState | null = null;
    let applying = false;
    let lastTargetKey = viewerTargetKeyOf(getViewerTarget());
    let lastMode = getViewerRouteMode();

    const apply = (message: PopoutState) => {
      applying = true;
      try {
        applyThemeAttribute(message.theme);
        // A fresh route every time (never the window's own hash, which links must not steer).
        useAppStore.setState({
          theme: message.theme,
          timezone: message.tz,
          route: { ...EMPTY_ROUTE, runId: message.runId, ...(message.q ? { q: message.q } : {}) },
        });
        if (getViewerRouteMode() !== message.mode) setViewerRouteMode(message.mode);
        if (viewerTargetKeyOf(getViewerTarget()) !== viewerTargetKeyOf(message.target)) {
          setViewerTarget(message.target, message.row);
        } else if (message.row) {
          setViewerTarget(getViewerTarget(), message.row);
        }
        lastTargetKey = viewerTargetKeyOf(getViewerTarget());
        lastMode = getViewerRouteMode();
        setTitle(popoutTitle(message.target, message.row));
        setLocator(message.target?.ref.locator ?? "");
      } finally {
        applying = false;
      }
      setPhase("ready");
    };

    const onToken = (event: MessageEvent) => {
      // Only the main window that opened us, only our origin.
      if (event.origin !== window.location.origin || event.source !== window.opener) return;
      const data = event.data as { type?: unknown; token?: unknown } | null;
      if (!data || data.type !== TOKEN_MESSAGE || typeof data.token !== "string" || !data.token) return;
      setAuthToken(data.token);
      tokenReady = true;
      if (pending) {
        const next = pending;
        pending = null;
        apply(next);
      }
    };
    window.addEventListener("message", onToken);

    if (channel) {
      channel.onmessage = (event) => {
        const data = event.data;
        if (!fromHost(data, hostRef.current) || !isMainToPopout(data)) return;
        if (data.type === "main-closed") {
          window.close();
          return;
        }
        if (tokenReady) apply(data);
        else pending = data;
      };
    }
    // A token copied with sessionStorage is fine too; never wait forever.
    const tokenTimer = setTimeout(() => {
      tokenReady = true;
      if (pending) {
        const next = pending;
        pending = null;
        apply(next);
      }
    }, TOKEN_WAIT_MS);

    // Changes made inside the window (history, tab choice) go back to the main window.
    const offAdapter = subscribeViewerAdapter(() => {
      if (applying) return;
      const target = getViewerTarget();
      const key = viewerTargetKeyOf(target);
      if (key !== lastTargetKey) {
        lastTargetKey = key;
        post({ type: "history", target: target ? cloneable(target) : null, row: null });
        setTitle(popoutTitle(target, null));
        setLocator(target?.ref.locator ?? "");
      }
      const mode = getViewerRouteMode();
      if (mode !== lastMode) {
        lastMode = mode;
        post({ type: "mode", mode });
      }
    });

    // A toolbar mark inside the window changed review data: the main grid refetches.
    // Route links inside the viewer (원본 행, IOC 발생 위치, 케이스 링크) open in the main window.
    const onLinkClick = (event: MouseEvent) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey)
        return;
      const anchor = (event.target as Element | null)?.closest?.("a[href^='#/']");
      const hash = anchor?.getAttribute("href");
      if (!anchor || !isRouteHash(hash)) return;
      event.preventDefault();
      post({ type: "navigate", hash });
    };
    document.addEventListener("click", onLinkClick, true);

    const onMarked = (event: Event) => {
      const runId = (event as CustomEvent<{ runId?: string }>).detail?.runId;
      if (runId) post({ type: "invalidate", runId });
    };
    window.addEventListener("rapidtriage:viewer-marked", onMarked);

    let boundsTimer: ReturnType<typeof setTimeout> | undefined;
    const onResize = () => {
      clearTimeout(boundsTimer);
      boundsTimer = setTimeout(() => writeBounds(windowBounds()), BOUNDS_SAVE_MS);
    };
    window.addEventListener("resize", onResize);
    const onUnload = () => {
      writeBounds(windowBounds());
      post({ type: "closed" });
    };
    window.addEventListener("beforeunload", onUnload);
    window.addEventListener("pagehide", onUnload);

    post({ type: "hello" });

    const commands: Command[] = [
      ...MARK_KEYS.map(
        ({ id, shortcut, label }): Command => ({
          id,
          label: `${label} (메인 창의 같은 행)`,
          group: "review",
          shortcut,
          icon: id.endsWith("bookmark") ? "bookmark" : "flag",
          disabledReason: () => (getViewerTarget() ? undefined : "뷰어에 표시된 행이 없습니다"),
          run: () => post({ type: "command", id }),
        }),
      ),
      {
        id: "navigate.rows-for-source",
        label: "같은 출처의 다른 행 (메인 창 목록)",
        group: "navigate",
        icon: "filter",
        disabledReason: () => (getViewerTarget()?.sourcePath ? undefined : "원본 파일 경로가 없는 행입니다."),
        run: () => post({ type: "command", id: "navigate.rows-for-source" }),
      },
      ...MODE_ORDER.map(
        (mode, index): Command => ({
          id: `popout.mode.${mode}`,
          label: `뷰어 모드: ${MODE_LABELS[mode]}`,
          group: "viewer",
          shortcut: String(index + 1),
          icon: "eye",
          disabledReason: () => (getViewerTarget() ? undefined : "뷰어에 표시된 행이 없습니다"),
          run: () => selectModeTab(mode),
        }),
      ),
      {
        id: "popout.return",
        label: "뷰어 창 닫고 메인 창으로 되돌리기",
        group: "viewer",
        icon: "panel-right",
        run: () => {
          post({ type: "return" });
          window.close();
        },
      },
    ];
    const offCommands = registerCommands(commands);

    return () => {
      clearTimeout(tokenTimer);
      clearTimeout(boundsTimer);
      window.removeEventListener("message", onToken);
      document.removeEventListener("click", onLinkClick, true);
      window.removeEventListener("rapidtriage:viewer-marked", onMarked);
      window.removeEventListener("resize", onResize);
      window.removeEventListener("beforeunload", onUnload);
      window.removeEventListener("pagehide", onUnload);
      offAdapter();
      offCommands();
      channel?.close();
      channelRef.current = null;
    };
  }, []);

  useEffect(() => {
    document.title = `뷰어 — ${title}`;
  }, [title]);

  return (
    <div className="popout-shell" data-testid="popout-shell">
      <header className="popout-bar">
        <span className="popout-bar-title">
          <Icon name="external" />
          뷰어 창
        </span>
        <span className="popout-bar-note" data-testid="popout-status">
          {phase === "orphan"
            ? "메인 창과 연결되지 않았습니다 — 이 창을 닫고 메인 창에서 Ctrl+Shift+V로 다시 여세요"
            : phase === "connecting"
              ? "메인 창과 연결하는 중…"
              : "메인 창의 선택을 따라갑니다 · J/K는 메인 창에서"}
        </span>
        <button
          type="button"
          className="button ghost"
          data-testid="popout-return"
          onClick={() => {
            post({ type: "return" });
            window.close();
          }}
        >
          <Icon name="panel-right" />
          메인 창으로 되돌리기
        </button>
      </header>
      <main
        id="viewer"
        className="popout-main"
        aria-label="뷰어 창"
        tabIndex={-1}
        data-row={locator || undefined}
      >
        {phase === "orphan" ? null : <Viewer drawer />}
      </main>
      <ToastRegion />
      <LiveRegion />
    </div>
  );
}
