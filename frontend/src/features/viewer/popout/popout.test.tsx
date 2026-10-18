import { act, cleanup, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { authToken, clearAuthToken, setAuthToken } from "../../../api/client";
import { registerCommand, resetCommandRegistry } from "../../../commands/registry";
import type { GridRow } from "../../../contracts/collection";
import type { ViewerTarget } from "../../../contracts/viewer";
import { parseHash } from "../../../router";
import { useAppStore } from "../../../state/store";
import { renderWithQuery } from "../../case/testUtils";
import { getViewerTarget, resetViewerAdapter } from "../adapter";
import { installFetch, preview } from "../testSupport";
import {
  openViewerPopout,
  POPOUT_COMMAND_ID,
  popoutCommands,
  popoutHostId,
  resetPopoutHost,
  returnViewerFromPopout,
  usePopoutHost,
} from "./host";
import { PopoutApp } from "./PopoutApp";
import {
  type ChannelLike,
  isMainToPopout,
  isPopoutToMain,
  isPopoutWindow,
  POPOUT_BOUNDS_KEY,
  popoutUrl,
  readBounds,
  setChannelFactory,
  TOKEN_MESSAGE,
  windowFeatures,
  writeBounds,
} from "./protocol";

/** In-memory BroadcastChannel: every channel sees the others' messages (never its own). */
function makeBus() {
  const channels = new Set<ChannelLike & { sent: unknown[] }>();
  const factory = (): ChannelLike => {
    const channel: ChannelLike & { sent: unknown[] } = {
      sent: [],
      onmessage: null,
      postMessage(message: unknown) {
        channel.sent.push(message);
        for (const other of channels) {
          if (other !== channel) other.onmessage?.(new MessageEvent("message", { data: message }));
        }
      },
      close() {
        channels.delete(channel);
      },
    };
    channels.add(channel);
    return channel;
  };
  /** A channel standing for the other window; its messages carry `host`. */
  const peer = (host = popoutHostId()) => {
    const channel = factory() as ChannelLike & { sent: unknown[] };
    const raw = channel.postMessage.bind(channel);
    channel.postMessage = (message: unknown) => raw({ ...(message as object), host });
    return channel;
  };
  return { factory, peer, channels };
}

const target: ViewerTarget = {
  runId: "r1",
  ref: { collection: "files", locator: "/files/1" },
  sourcePath: "C:/evidence/report.txt",
};
const row = {
  rowKey: "files:/files/1",
  ref: target.ref,
  title: "report.txt",
  sourcePath: target.sourcePath,
  timestamp: null,
  tags: [],
  reviewStatus: null,
  fields: {},
} as unknown as GridRow;

beforeEach(() => {
  resetCommandRegistry();
  resetPopoutHost();
  resetViewerAdapter();
  window.localStorage.removeItem(POPOUT_BOUNDS_KEY);
  window.location.hash = "#/case/r1/explore/files";
  useAppStore.getState().syncRouteFromLocation(parseHash(window.location.hash));
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  clearAuthToken();
});

describe("viewer window protocol (U-F2)", () => {
  it("opens the same bundle with ?popout=viewer — no token, no route in the URL", () => {
    const url = popoutUrl({ origin: "http://127.0.0.1:8806", pathname: "/v2/" });
    expect(url).toBe("http://127.0.0.1:8806/v2/?popout=viewer");
    expect(url).not.toMatch(/token|#/);
    expect(isPopoutWindow("?popout=viewer")).toBe(true);
    expect(isPopoutWindow("?popout=other")).toBe(false);
  });

  it("validates messages both ways; only review marks may be forwarded", () => {
    expect(isMainToPopout({ type: "state", target, row: null, tz: "local", theme: null, runId: "r1" })).toBe(
      true,
    );
    expect(isMainToPopout({ type: "state", target: { nope: 1 }, tz: "local" })).toBe(false);
    expect(isMainToPopout({ type: "main-closed" })).toBe(true);
    expect(isPopoutToMain({ type: "command", id: "review.mark.relevant" })).toBe(true);
    expect(isPopoutToMain({ type: "command", id: "case.delete" })).toBe(false);
    expect(isPopoutToMain({ type: "history", target: null, row: null })).toBe(true);
    expect(isPopoutToMain({ type: "token", token: "x" })).toBe(false);
  });

  it("remembers window bounds; ignores absurd ones", () => {
    expect(readBounds()).toBeNull();
    expect(windowFeatures(null, 1920)).toBe("popup,width=900,height=900,left=980,top=40");
    writeBounds({ left: 2000, top: 10, width: 1200, height: 1000 });
    expect(windowFeatures(readBounds())).toBe("popup,width=1200,height=1000,left=2000,top=10");
    writeBounds({ left: 0, top: 0, width: 10, height: 10 });
    expect(readBounds()?.width).toBe(1200);
  });
});

describe("main window host (U-F2)", () => {
  function fakePopup() {
    const popup = { closed: false, focus: vi.fn(), close: vi.fn(), postMessage: vi.fn() };
    popup.close.mockImplementation(() => {
      popup.closed = true;
    });
    return popup;
  }

  it("Ctrl+Shift+V opens the window with the remembered bounds; state follows the main store", () => {
    const bus = makeBus();
    setChannelFactory(bus.factory);
    vi.stubGlobal("BroadcastChannel", class {});
    const popup = fakePopup();
    const open = vi.spyOn(window, "open").mockReturnValue(popup as unknown as Window);
    writeBounds({ left: 1920, top: 0, width: 1000, height: 1080 });
    const commands = popoutCommands();
    expect(commands[0]?.shortcut).toBe("Ctrl+Shift+V");
    expect(openViewerPopout()).toBe("opened");
    expect(open).toHaveBeenCalledWith(
      `${window.location.origin}${window.location.pathname}?popout=viewer&host=${popoutHostId()}`,
      // One window per console tab (review #3): the name carries the host id.
      `rapidforensic-viewer-${popoutHostId()}`,
      "popup,width=1000,height=1080,left=1920,top=0",
    );
    expect(usePopoutHost.getState().status).toBe("open");
    const other = bus.peer();
    // hello → token by postMessage (to the popup, our origin) + the state on the channel.
    setAuthToken("secret-token");
    other.postMessage({ type: "hello" });
    expect(popup.postMessage).toHaveBeenCalledWith(
      { type: TOKEN_MESSAGE, token: "secret-token" },
      window.location.origin,
    );
    const states = () => bus.channels.size && [...bus.channels].flatMap((c) => c.sent);
    expect(JSON.stringify(states())).not.toContain("secret-token");
    // J/K in the main grid → the store's target changes → one state message.
    act(() => useAppStore.getState().setViewerTarget(target, { row }));
    const received: unknown[] = [];
    other.onmessage = (event) => received.push(event.data);
    act(() =>
      useAppStore.getState().setViewerTarget({ ...target, ref: { ...target.ref, locator: "/files/2" } }),
    );
    expect(received).toHaveLength(1);
    expect((received[0] as { target: ViewerTarget }).target.ref.locator).toBe("/files/2");
    // A second Ctrl+Shift+V focuses the open window.
    expect(openViewerPopout()).toBe("focused");
    expect(popup.focus).toHaveBeenCalled();
  });

  it("runs only forwarded review marks; history and mode come back into the store", async () => {
    const bus = makeBus();
    setChannelFactory(bus.factory);
    vi.stubGlobal("BroadcastChannel", class {});
    vi.spyOn(window, "open").mockReturnValue(fakePopup() as unknown as Window);
    const marked = vi.fn();
    registerCommand({ id: "review.mark.relevant", label: "관련", group: "review", run: marked });
    openViewerPopout();
    const other = bus.peer();
    other.postMessage({ type: "command", id: "review.mark.relevant" });
    other.postMessage({ type: "command", id: "case.delete" });
    await waitFor(() => expect(marked).toHaveBeenCalledTimes(1));
    other.postMessage({ type: "history", target, row: null });
    expect(useAppStore.getState().viewerTarget?.ref.locator).toBe("/files/1");
    other.postMessage({ type: "mode", mode: "hex" });
    expect(useAppStore.getState().route.mode).toBe("hex");
  });

  it("the popup closing (× or 되돌리기) brings the pane back; blocked popups say why", () => {
    const bus = makeBus();
    setChannelFactory(bus.factory);
    vi.stubGlobal("BroadcastChannel", class {});
    const popup = fakePopup();
    vi.spyOn(window, "open")
      .mockReturnValueOnce(popup as unknown as Window)
      .mockReturnValueOnce(null);
    // Fake timers before opening: the closed poll and the grace both run on them (review #14).
    vi.useFakeTimers();
    openViewerPopout();
    // A reload (closed, then hello within the grace) keeps it open; a real close does not.
    const other = bus.peer();
    other.postMessage({ type: "closed" });
    other.postMessage({ type: "hello" });
    vi.advanceTimersByTime(2000);
    expect(usePopoutHost.getState().status).toBe("open");
    // Another console tab's window (other host id) cannot close or steer ours.
    bus.peer("someone-else").postMessage({ type: "return" });
    expect(usePopoutHost.getState().status).toBe("open");
    popup.closed = true;
    other.postMessage({ type: "closed" });
    vi.advanceTimersByTime(2000);
    vi.useRealTimers();
    expect(usePopoutHost.getState().status).toBe("closed");
    expect(openViewerPopout()).toBe("blocked");
    expect(useAppStore.getState().notice?.text).toMatch(/팝업을 차단/);
    expect(usePopoutHost.getState().blocked).toBe(true);
  });

  it("a route link from the window opens in the main window, only for the same case", () => {
    const bus = makeBus();
    setChannelFactory(bus.factory);
    vi.stubGlobal("BroadcastChannel", class {});
    vi.spyOn(window, "open").mockReturnValue(fakePopup() as unknown as Window);
    openViewerPopout();
    const other = bus.peer();
    other.postMessage({ type: "navigate", hash: "#/case/r1/explore/artifacts/browser" });
    expect(useAppStore.getState().route.collection).toBe("artifacts");
    expect(useAppStore.getState().route.kind).toBe("browser");
    // Another case, or something that is not a route: ignored.
    other.postMessage({ type: "navigate", hash: "#/case/other/explore/files" });
    other.postMessage({ type: "navigate", hash: "javascript:alert(1)" });
    expect(useAppStore.getState().route.runId).toBe("r1");
    expect(useAppStore.getState().route.kind).toBe("browser");
  });

  it("되돌리기 closes the window; the command is disabled while the viewer is in the pane", () => {
    const bus = makeBus();
    setChannelFactory(bus.factory);
    vi.stubGlobal("BroadcastChannel", class {});
    const popup = fakePopup();
    vi.spyOn(window, "open").mockReturnValue(popup as unknown as Window);
    const [, back] = popoutCommands();
    const ctx = {
      runId: "r1",
      collection: null,
      selectedRowKeys: [],
      focusedRowKey: null,
      viewerHasTarget: false,
      runIsActive: false,
    };
    expect(back?.disabledReason?.(ctx)).toBe("뷰어가 새 창에 열려 있지 않습니다");
    openViewerPopout();
    expect(back?.disabledReason?.(ctx)).toBeUndefined();
    returnViewerFromPopout();
    expect(popup.close).toHaveBeenCalled();
    expect(usePopoutHost.getState().status).toBe("closed");
    expect(popoutCommands()[0]?.id).toBe(POPOUT_COMMAND_ID);
  });
});

describe("viewer window (PopoutApp)", () => {
  it("waits for the opener's token, then shows the main window's row; title names the row", async () => {
    installFetch({
      "source-preview": () =>
        preview({ path: "C:/evidence/report.txt", name: "report.txt", preview_type: "text", text: "hello" }),
      "source-metadata": () => ({ path: "C:/evidence/report.txt", size: 5, hashes: {} }),
    });
    window.history.replaceState(null, "", "/?popout=viewer&host=h1");
    const bus = makeBus();
    setChannelFactory(bus.factory);
    const opener = {} as Window;
    vi.stubGlobal("opener", opener);
    const main = bus.peer("h1");
    // Another console tab's state is ignored.
    const stranger = bus.peer("h2");
    const fromPopout: unknown[] = [];
    main.onmessage = (event) => fromPopout.push(event.data);
    renderWithQuery(<PopoutApp />);
    expect(fromPopout).toContainEqual({ type: "hello", host: "h1" });
    stranger.postMessage({
      type: "state",
      target: { ...target, ref: { ...target.ref, locator: "/x" } },
      row: null,
      tz: "utc",
      theme: null,
      runId: "r9",
    });
    main.postMessage({ type: "state", target, row, tz: "utc", theme: "light", runId: "r1" });
    // Not shown before the token (unless the timeout passes).
    expect(getViewerTarget()).toBeNull();
    // A token from anyone but the opener is ignored.
    window.dispatchEvent(
      new MessageEvent("message", {
        data: { type: TOKEN_MESSAGE, token: "evil" },
        origin: window.location.origin,
      }),
    );
    expect(authToken()).toBe("");
    act(() => {
      window.dispatchEvent(
        new MessageEvent("message", {
          data: { type: TOKEN_MESSAGE, token: "t-123" },
          origin: window.location.origin,
          source: opener as unknown as MessageEventSource,
        }),
      );
    });
    expect(authToken()).toBe("t-123");
    await waitFor(() => expect(getViewerTarget()?.ref.locator).toBe("/files/1"));
    await waitFor(() => expect(document.title).toBe("뷰어 — report.txt"));
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(screen.getByTestId("popout-status").textContent).toContain("메인 창의 선택을 따라갑니다");
    expect(window.location.href).not.toContain("t-123");
    expect(getViewerTarget()?.ref.locator).toBe("/files/1");
    window.history.replaceState(null, "", "/");
  });

  it("route links inside the window go to the main window; the window's own route stays clean", async () => {
    window.history.replaceState(null, "", "/?popout=viewer&host=h1");
    installFetch({
      "source-preview": () => preview({}),
      "source-metadata": () => ({ path: "x", size: 1, hashes: {} }),
    });
    setAuthToken("t");
    const bus = makeBus();
    setChannelFactory(bus.factory);
    const opener = {} as Window;
    vi.stubGlobal("opener", opener);
    const main = bus.peer("h1");
    const fromPopout: Array<{ type: string; hash?: string }> = [];
    main.onmessage = (event) => fromPopout.push(event.data);
    renderWithQuery(<PopoutApp />);
    main.postMessage({ type: "state", target, row, tz: "utc", theme: null, runId: "r1" });
    await waitFor(() => expect(getViewerTarget()?.ref.locator).toBe("/files/1"));
    const link = document.createElement("a");
    link.href = "#/case/r1/explore/artifacts/browser";
    link.textContent = "원본 아티팩트 행으로 이동";
    document.querySelector("#viewer")?.appendChild(link);
    const before = window.location.hash;
    link.click();
    expect(fromPopout).toContainEqual({
      type: "navigate",
      hash: "#/case/r1/explore/artifacts/browser",
      host: "h1",
    });
    expect(window.location.hash).toBe(before);
    // The next state never carries a route the window picked up from its own hash.
    useAppStore.setState({ route: parseHash("#/case/zzz/explore/files") });
    main.postMessage({ type: "state", target, row, tz: "utc", theme: null, runId: "r1" });
    expect(useAppStore.getState().route).toEqual({ runId: "r1", collection: null });
    // The server catalogue is requested once the window is connected (review #9).
    await waitFor(() =>
      expect(vi.mocked(fetch).mock.calls.some(([url]) => String(url).includes("/api/meta/families"))).toBe(
        true,
      ),
    );
    link.remove();
    window.history.replaceState(null, "", "/");
  });

  it("without an opener it explains instead of showing a viewer", () => {
    vi.stubGlobal("opener", null);
    setChannelFactory(makeBus().factory);
    renderWithQuery(<PopoutApp />);
    expect(screen.getByTestId("popout-status").textContent).toMatch(/메인 창과 연결되지 않았습니다/);
  });
});
