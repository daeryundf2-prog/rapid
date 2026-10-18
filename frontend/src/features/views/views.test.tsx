// biome-ignore-all lint/a11y: tests drive ARIA widgets through their DOM roles
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RunTree } from "../../api/runs";
import { ViewSwitch } from "../../app/ViewSwitch";
import { resetCommandRegistry } from "../../commands/registry";
import type { GridRow } from "../../contracts/collection";
import { parseHash, serializeRoute } from "../../router";
import { dispatchShortcut, eventToShortcut } from "../../shortcuts";
import { resetAppStore, useAppStore } from "../../state/store";
import { useGridLocalStore } from "../grid/adapter";
import { installFetch, jsonResponse, mockLayout, queryWrapper, resetGridStore } from "../grid/testSupport";
import { useViewPrefs } from "../review/viewPrefs";
import { effectiveView, viewAvailability, viewDisabledReason } from "./availability";
import { ChatView } from "./ChatView";
import { groupConversations, highlightParts, highlightTerms, isMessageRow } from "./chat";
import { HistogramView } from "./HistogramView";
import { barsFromRows, barsFromTree, rangeOf, rebucket, type TimelineHistogramPayload } from "./histogram";
import { loadThumbBlob, THUMB_CONCURRENCY, THUMB_SIZE, ThumbnailView } from "./ThumbnailView";
import { createLimiter, gridMove, isImageRow, sortThumbs } from "./thumbnails";
import { useToolbarLead } from "./toolbarSlot";

let restoreLayout: () => void = () => {};

beforeEach(() => {
  resetCommandRegistry();
  resetAppStore();
  resetGridStore();
  restoreLayout = mockLayout(800, 600);
});

afterEach(() => {
  cleanup();
  restoreLayout();
  resetCommandRegistry();
  vi.unstubAllGlobals();
});

function row(partial: Partial<GridRow> & { rowKey: string }): GridRow {
  return {
    ref: { collection: "artifacts", locator: partial.rowKey },
    title: partial.rowKey,
    sourcePath: null,
    timestamp: null,
    artifactType: null,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: {},
    ...partial,
  };
}

function renderQ(ui: React.ReactElement) {
  const { wrapper } = queryWrapper();
  return render(ui, { wrapper });
}

// --- availability -------------------------------------------------------------

describe("view availability matrix", () => {
  it("enables each view only on the nodes that can show it", () => {
    const matrix = (id: Parameters<typeof viewAvailability>[0]["id"], kind?: string) => {
      const a = viewAvailability({ id, kind });
      return (["columns", "thumbnails", "chat", "histogram"] as const).map((v) => (a[v] ? 0 : 1)).join("");
    };
    expect(matrix("files")).toBe("1101");
    expect(matrix("artifacts", "media-image")).toBe("1101");
    expect(matrix("artifacts", "synthetic-media")).toBe("1101");
    expect(matrix("artifacts", "kakaotalk-windows")).toBe("1011");
    expect(matrix("artifacts", "kakaotalk-macos")).toBe("1011");
    expect(matrix("artifacts", "mobile-export")).toBe("1011");
    // r2 M1: Teams·Slack·… desktop messenger rows (chat-message).
    expect(matrix("artifacts", "windows-messenger")).toBe("1011");
    expect(matrix("artifacts", "eventlog")).toBe("1001");
    expect(matrix("artifacts")).toBe("1001");
    expect(matrix("timeline")).toBe("1001");
    expect(matrix("docs")).toBe("1001");
    expect(matrix("search")).toBe("1001");
    expect(matrix("indicators")).toBe("1000");
    expect(matrix("review")).toBe("1000");
    expect(matrix("outputs")).toBe("1000");
    expect(matrix("intake")).toBe("1000");
    expect(matrix(null)).toBe("1000");
  });

  it("explains why a view is unavailable and falls back to the column view", () => {
    expect(viewDisabledReason("chat", { id: "files" })).toMatch(/카카오톡/);
    expect(viewDisabledReason("thumbnails", { id: "timeline" })).toMatch(/파일 노드/);
    expect(effectiveView("chat", { id: "files" })).toBe("columns");
    expect(effectiveView("thumbnails", { id: "files" })).toBe("thumbnails");
    expect(effectiveView(undefined, { id: "files" })).toBe("columns");
  });
});

// --- URL --------------------------------------------------------------------

describe("view= route parameter", () => {
  it("round-trips through parseHash / serializeRoute and omits the default", () => {
    for (const view of ["thumbnails", "chat", "histogram"] as const) {
      const hash = serializeRoute({ runId: "r", collection: "files", view });
      expect(hash).toContain(`view=${view}`);
      expect(parseHash(hash).view).toBe(view);
    }
    expect(serializeRoute({ runId: "r", collection: "files", view: "columns" })).toBe(
      "#/case/r/explore/files",
    );
    expect(parseHash("#/case/r/explore/files?view=columns").view).toBeUndefined();
    expect(parseHash("#/case/r/explore/files?view=worldmap").view).toBeUndefined();
    const full = "#/case/r/explore/artifacts/mobile-export?q=%ED%9A%8C%EC%9D%98&view=chat";
    expect(serializeRoute(parseHash(full))).toBe(full);
  });

  it("normalises Alt+Shift+digit whatever character the layout produces", () => {
    const ev = (key: string, code: string) =>
      new KeyboardEvent("keydown", { key, code, altKey: true, shiftKey: true });
    expect(eventToShortcut(ev("!", "Digit1"))).toBe("Alt+Shift+1");
    expect(eventToShortcut(ev("@", "Digit2"))).toBe("Alt+Shift+2");
    expect(eventToShortcut(ev("4", "Digit4"))).toBe("Alt+Shift+4");
  });
});

/** Stand-in for the DataGrid: renders the toolbar lead (the view switch) on its own toolbar line. */
function GridStub() {
  const lead = useToolbarLead();
  return (
    <div>
      <div data-testid="grid-stub-toolbar">{lead}</div>
      GRID
    </div>
  );
}

describe("ViewSwitch", () => {
  function routeTo(collection: "files" | "timeline" | "review", view?: "thumbnails" | "histogram") {
    act(() => useAppStore.getState().navigate({ runId: "run-1", collection, ...(view ? { view } : {}) }));
  }

  it("disables unavailable views with a reason and writes view= on switch", () => {
    installFetch({ "/timeline-histogram": () => jsonResponse({ parsed_events: 0, buckets: [] }) });
    useGridLocalStore.setState((s) => ({ route: { ...s.route, collection: { id: "timeline" } } }));
    routeTo("timeline");
    renderQ(
      <ViewSwitch>
        <GridStub />
      </ViewSwitch>,
    );
    expect(screen.getByText("GRID")).toBeTruthy();
    // Column view: the switch rides the grid's toolbar line (visual-polish S1), not a row of its own.
    const bar = screen.getByRole("toolbar", { name: "보기 전환" });
    expect(bar.closest('[data-testid="grid-stub-toolbar"]')).toBeTruthy();
    const thumbs = screen.getByRole("button", { name: "썸네일 보기" });
    expect(thumbs.getAttribute("aria-disabled")).toBe("true");
    expect(thumbs.getAttribute("data-disabled-reason")).toMatch(/파일 노드/);
    fireEvent.click(thumbs);
    expect(useAppStore.getState().route.view).toBeUndefined();
    fireEvent.click(screen.getByRole("button", { name: "히스토그램 보기" }));
    expect(useAppStore.getState().route.view).toBe("histogram");
    expect(window.location.hash).toContain("view=histogram");
    expect(screen.queryByText("GRID")).toBeNull();
    // Other views keep the switch on a row of their own.
    expect(screen.getByRole("toolbar", { name: "보기 전환" }).closest(".view-switch-row")).toBeTruthy();
  });

  it("a node with only the column view (리뷰보드) shows no switch (visual-polish S2)", () => {
    routeTo("review");
    renderQ(
      <ViewSwitch>
        <GridStub />
      </ViewSwitch>,
    );
    expect(screen.getByText("GRID")).toBeTruthy();
    expect(screen.queryByRole("toolbar", { name: "보기 전환" })).toBeNull();
  });

  it("switches views with Alt+Shift+1–4 and drops an unavailable view= from the URL", () => {
    installFetch({ "/files": () => jsonResponse({ candidates: [], total: 0 }) });
    routeTo("files");
    renderQ(
      <ViewSwitch>
        <div>GRID</div>
      </ViewSwitch>,
    );
    const key = (digit: string, char: string) =>
      new KeyboardEvent("keydown", {
        key: char,
        code: `Digit${digit}`,
        altKey: true,
        shiftKey: true,
        cancelable: true,
        bubbles: true,
      });
    act(() => {
      dispatchShortcut(key("2", "@"));
    });
    expect(useAppStore.getState().route.view).toBe("thumbnails");
    act(() => {
      dispatchShortcut(key("3", "#")); // chat: not available on files → reason, no change
    });
    expect(useAppStore.getState().route.view).toBe("thumbnails");
    act(() => {
      dispatchShortcut(key("1", "!"));
    });
    expect(useAppStore.getState().route.view).toBeUndefined();

    act(() => useAppStore.getState().navigate({ runId: "run-1", collection: "files", view: "chat" }));
    expect(useAppStore.getState().route.view).toBeUndefined();
    expect(screen.getByText("GRID")).toBeTruthy();
  });
});

// --- thumbnails ---------------------------------------------------------------

describe("thumbnail loading", () => {
  it("createLimiter runs at most N tasks at once and drops aborted queued tasks", async () => {
    const limit = createLimiter(2);
    let running = 0;
    let peak = 0;
    const releases: Array<() => void> = [];
    const task = () =>
      new Promise<number>((resolve) => {
        running += 1;
        peak = Math.max(peak, running);
        releases.push(() => {
          running -= 1;
          resolve(running);
        });
      });
    const aborter = new AbortController();
    const started = [limit(undefined, task), limit(undefined, task), limit(undefined, task)];
    const dropped = limit(aborter.signal, task);
    aborter.abort();
    await expect(dropped).rejects.toBeDefined();
    expect(peak).toBe(2);
    releases.shift()?.();
    await started[0];
    await waitFor(() => expect(releases.length).toBe(2));
    for (const release of releases.splice(0)) release();
    await Promise.all(started);
    expect(peak).toBe(2);
  });

  it("loads the server thumbnail and falls back to the original only when it fails", async () => {
    const calls = installFetch({
      "/source-thumbnail": (url) =>
        url.searchParams.get("path")?.endsWith("bad.png")
          ? jsonResponse({ detail: "unsupported" }, 415)
          : new Response("thumb", { status: 200 }),
      "/source-file": () => new Response("original", { status: 200 }),
    });
    const ok = await loadThumbBlob("run-1", "C:/x/a.jpg", new AbortController().signal);
    expect(await ok.text()).toBe("thumb");
    expect(calls.map((c) => c.url.split("?")[0])).toEqual(["/api/runs/run-1/source-thumbnail"]);
    expect(new URL(calls[0]?.url ?? "", "http://x").searchParams.get("size")).toBe(String(THUMB_SIZE));

    const fallback = await loadThumbBlob("run-1", "C:/x/bad.png", new AbortController().signal);
    expect(await fallback.text()).toBe("original");
    expect(calls.slice(1).map((c) => c.url.split("?")[0])).toEqual([
      "/api/runs/run-1/source-thumbnail",
      "/api/runs/run-1/source-file",
    ]);
    expect(THUMB_CONCURRENCY).toBe(6);
  });
});

describe("thumbnail model", () => {
  it("keeps image rows only and sorts by name / date / size", () => {
    const rows = [
      row({ rowKey: "b", sourcePath: "C:/x/b.PNG", timestamp: "2026-01-02", fields: { size: 5 } }),
      row({ rowKey: "a", sourcePath: "C:/x/a.jpg", timestamp: "2026-01-03", fields: { size: 50 } }),
      row({ rowKey: "t", sourcePath: "C:/x/t.txt" }),
      row({ rowKey: "v", sourcePath: "C:/x/v.jpg", artifactType: "media-video" }),
      row({ rowKey: "c", sourcePath: "C:/x/c.gif", fields: { size: 20 } }),
    ];
    const images = rows.filter(isImageRow);
    expect(images.map((r) => r.rowKey)).toEqual(["b", "a", "c"]);
    expect(sortThumbs(images, "name-asc").map((r) => r.rowKey)).toEqual(["a", "b", "c"]);
    expect(sortThumbs(images, "date-desc").map((r) => r.rowKey)).toEqual(["a", "b", "c"]);
    expect(sortThumbs(images, "size-asc").map((r) => r.rowKey)).toEqual(["b", "c", "a"]);
  });

  it("moves like an ARIA grid", () => {
    // 7 tiles, 3 per row: 0 1 2 / 3 4 5 / 6
    expect(gridMove(0, { key: "ArrowRight" }, 3, 7)).toBe(1);
    expect(gridMove(2, { key: "ArrowRight" }, 3, 7)).toBe(3);
    expect(gridMove(1, { key: "ArrowDown" }, 3, 7)).toBe(4);
    expect(gridMove(4, { key: "ArrowDown" }, 3, 7)).toBe(4); // no tile below
    expect(gridMove(4, { key: "ArrowUp" }, 3, 7)).toBe(1);
    expect(gridMove(4, { key: "Home" }, 3, 7)).toBe(3);
    expect(gridMove(4, { key: "End" }, 3, 7)).toBe(5);
    expect(gridMove(6, { key: "End" }, 3, 7)).toBe(6);
    expect(gridMove(4, { key: "Home", ctrlKey: true }, 3, 7)).toBe(0);
    expect(gridMove(0, { key: "End", ctrlKey: true }, 3, 7)).toBe(6);
    expect(gridMove(0, { key: "x" }, 3, 7)).toBeNull();
  });
});

describe("ThumbnailView", () => {
  const names = ["a.jpg", "b.png", "c.gif", "d.jpeg", "e.bmp", "f.webp", "g.tif", "notes.txt"];

  it("renders a keyboard-navigable grid and opens the viewer in image mode", async () => {
    installFetch({
      "/files": () =>
        jsonResponse({
          candidates: names.map((name, i) => ({
            path: `C:/case/${name}`,
            name,
            extension: name.split(".")[1],
            size: i,
          })),
          total: names.length,
        }),
    });
    renderQ(<ThumbnailView />);
    const grid = await screen.findByRole("grid", { name: /썸네일 격자, 이미지 7개/ });
    const cells = () => Array.from(grid.querySelectorAll<HTMLElement>('[role="gridcell"]'));
    await waitFor(() => expect(cells().length).toBe(7));
    expect(cells().filter((c) => c.tabIndex === 0)).toHaveLength(1);
    // 800 px / 152 px tiles = 5 per row.
    expect(grid.getAttribute("aria-colcount")).toBe("5");

    act(() => cells()[0]?.focus());
    expect(useGridLocalStore.getState().target?.sourcePath).toBe("C:/case/a.jpg");
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "ArrowRight" });
    await waitFor(() => expect(document.activeElement?.getAttribute("data-thumb-index")).toBe("1"));
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "ArrowDown" });
    await waitFor(() => expect(document.activeElement?.getAttribute("data-thumb-index")).toBe("6"));
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "Home", ctrlKey: true });
    await waitFor(() => expect(document.activeElement?.getAttribute("data-thumb-index")).toBe("0"));
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "End" });
    await waitFor(() => expect(document.activeElement?.getAttribute("data-thumb-index")).toBe("4"));

    const before = useGridLocalStore.getState().viewerFocusRequests;
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "Enter" });
    const state = useGridLocalStore.getState();
    expect(state.target?.preferredMode).toBe("image");
    expect(state.target?.sourcePath).toBe("C:/case/e.bmp");
    expect(state.viewerFocusRequests).toBe(before + 1);

    fireEvent.keyDown(document.activeElement as HTMLElement, { key: " " });
    expect([...useGridLocalStore.getState().selectedKeys]).toEqual([state.focusedRow?.rowKey]);
    expect(await screen.findByText("1개 선택")).toBeTruthy();
  });

  it("also draws media-image artifacts and loads tiles from source-thumbnail", async () => {
    const calls = installFetch({
      "/files": () =>
        jsonResponse({ candidates: [{ path: "C:/a.txt", name: "a.txt", extension: "txt" }], total: 1 }),
      "/artifacts": (url) =>
        url.searchParams.getAll("kind").includes("media-image")
          ? jsonResponse({
              artifacts: {
                "media-image": {
                  total: 2,
                  artifacts: [
                    { artifact_type: "media-image", path: "C:/case/p1.jpg", details: {} },
                    { artifact_type: "media-image", path: "C:/case/p2.png", details: {} },
                  ],
                },
              },
            })
          : jsonResponse({ artifacts: {} }),
      "/source-thumbnail": () => new Response("thumb", { status: 200 }),
    });
    renderQ(<ThumbnailView />);
    expect(await screen.findByRole("grid", { name: /이미지 2개/ })).toBeTruthy();
    expect(await screen.findByText(/이미지 2건 \(\d+행 검사\)/)).toBeTruthy();
    await waitFor(() =>
      expect(calls.some((c) => c.url.includes("/api/runs/") && c.url.includes("/source-thumbnail?"))).toBe(
        true,
      ),
    );
    const thumb = calls.find((c) => c.url.includes("/source-thumbnail"));
    expect(new URL(thumb?.url ?? "", "http://x").searchParams.get("size")).toBe(String(THUMB_SIZE));
  });

  it("explains an empty node", async () => {
    installFetch({
      "/files": () => jsonResponse({ candidates: [{ path: "C:/a.txt", name: "a.txt" }], total: 1 }),
    });
    renderQ(<ThumbnailView />);
    expect(await screen.findByText("이 노드에는 썸네일로 표시할 이미지가 없습니다.")).toBeTruthy();
  });

  it("미디어 탐색기: 유사 사진 찾기 narrows the grid, selects the set, and keeps the blur", async () => {
    installFetch({
      "/files": () =>
        jsonResponse({
          candidates: ["a.jpg", "b.png", "c.gif"].map((name) => ({ path: `C:/case/${name}`, name })),
          total: 3,
        }),
      "/media/similar": () =>
        jsonResponse({
          run_id: "run-1",
          ref: { path: "C:/case/a.jpg", record_index: 0, perceptual_hash: "0", sha256: null },
          max_distance: 8,
          limit: 100,
          items: [
            {
              path: "C:\\case\\b.png",
              name: "b.png",
              kind: "media-image",
              record_index: 1,
              locator: "/artifacts/1",
              distance: 3,
              same_hash: false,
              sha256: null,
              camera: null,
              captured_at: null,
            },
          ],
          counts: { indexed: 3, with_phash: 3, same_hash: 0, near: 1, matched: 1, returned: 1 },
        }),
    });
    useViewPrefs.setState({ mediaBlur: true });
    renderQ(<ThumbnailView />);
    const grid = await screen.findByRole("grid", { name: /이미지 3개/ });
    const cells = () => Array.from(grid.querySelectorAll<HTMLElement>('[role="gridcell"]'));
    await waitFor(() => expect(cells().length).toBe(3));
    // The panel works on the active tile (the roving tab stop, a.jpg until focus moves).
    act(() => cells()[0]?.focus());
    fireEvent.click(screen.getByTestId("media-panel-similar"));
    expect(screen.getByTestId("media-panel-similar").getAttribute("aria-pressed")).toBe("true");
    const panel = await screen.findByTestId("media-panel");
    expect(panel.textContent).toContain("유사 사진 찾기 — a.jpg");
    await waitFor(() => expect(panel.textContent).toContain("pHash 거리 3"));
    fireEvent.click(screen.getByRole("button", { name: "격자에 이 묶음만" }));
    expect(await screen.findByRole("grid", { name: /이미지 2개/ })).toBeTruthy();
    expect(screen.getByTestId("media-narrow").textContent).toContain("2건 표시");
    expect(document.querySelector(".thumb-view")?.hasAttribute("data-media-blur")).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "이 묶음 선택(태그용)" }));
    expect(useGridLocalStore.getState().selectedKeys.size).toBe(2);
    expect(await screen.findByText("2개 선택")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "모두 보기" }));
    expect(await screen.findByRole("grid", { name: /이미지 3개/ })).toBeTruthy();
    useViewPrefs.setState({ mediaBlur: false });
  });
});

// --- chat -------------------------------------------------------------------

function messageRow(i: number, details: Record<string, unknown>, type = "mobile-message") {
  return {
    provider: "mobile-export-artifacts",
    artifact_type: type,
    path: "C:/export/chat.json",
    details: { source_index: i, ...details },
  };
}

const CHAT_ROWS = [
  messageRow(0, {
    conversation_id: "room-a",
    sender: "김",
    timestamp: "2026-10-01T01:00:00Z",
    message_text: "내일 회의 10시",
  }),
  messageRow(1, {
    conversation_id: "room-b",
    sender: "박",
    timestamp: "2026-10-03T09:00:00Z",
    message_text: "자료 보냄",
    attachment_name: "회의록.pdf",
  }),
  messageRow(2, {
    conversation_id: "room-a",
    sender: "이",
    timestamp: "2026-10-01T00:30:00Z",
    raw: { message: "안녕하세요" },
  }),
  messageRow(3, {
    conversation_id: "room-b",
    sender: "최",
    timestamp: "2026-10-02T09:00:00Z",
    message_text: "확인",
  }),
  messageRow(4, { app: "KakaoTalk" }, "mobile-app"),
];

describe("chat model", () => {
  it("groups message rows into time-ordered conversations, newest conversation first", () => {
    const rows = CHAT_ROWS.map((raw, i) =>
      row({
        rowKey: `m${i}`,
        artifactType: raw.artifact_type,
        sourcePath: raw.path,
        fields: { details: raw.details, kind: "mobile-export" },
      }),
    );
    expect(rows.filter(isMessageRow)).toHaveLength(4);
    const conversations = groupConversations(rows);
    expect(conversations.map((c) => c.id)).toEqual(["room-b", "room-a"]);
    expect(conversations[1]?.messages.map((m) => m.text)).toEqual(["안녕하세요", "내일 회의 10시"]);
    expect(conversations[0]?.messages[1]?.attachments).toEqual(["회의록.pdf"]);
    expect(conversations[0]?.participants).toEqual(["최", "박"]);
  });

  it("highlights every query term case-insensitively", () => {
    expect(highlightTerms('회의 "PDF",x')).toEqual(["회의", "PDF", "x"]);
    expect(highlightParts("회의록.pdf 회의", ["회의", "pdf"])).toEqual([
      { text: "회의", hit: true },
      { text: "록.", hit: false },
      { text: "pdf", hit: true },
      { text: " ", hit: false },
      { text: "회의", hit: true },
    ]);
    expect(highlightParts("a+b", ["+"])).toEqual([
      { text: "a", hit: false },
      { text: "+", hit: true },
      { text: "b", hit: false },
    ]);
  });
});

describe("ChatView", () => {
  it("lists conversations, highlights the route keyword and opens a bubble in the viewer", async () => {
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, collection: { id: "artifacts", kind: "mobile-export" }, q: "회의" },
    }));
    installFetch({
      "/artifacts": () =>
        jsonResponse({ artifacts: { "mobile-export": { artifacts: CHAT_ROWS, total: CHAT_ROWS.length } } }),
    });
    renderQ(<ChatView />);
    const list = await screen.findByRole("listbox", { name: /대화 목록, 2개/ });
    const options = list.querySelectorAll('[role="option"]');
    expect(options[0]?.getAttribute("aria-selected")).toBe("true");
    expect(options[0]?.textContent).toContain("room-b");

    // Newest conversation (room-b): the attachment name carries the keyword.
    await waitFor(() => expect(document.querySelectorAll("mark.chat-hit")).toHaveLength(1));
    expect(screen.getByText(/검색어 일치 1건/)).toBeTruthy();

    // Switch to room-a with the keyboard and enter the bubbles with →.
    fireEvent.keyDown(options[0] as HTMLElement, { key: "ArrowDown" });
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "Enter" });
    await waitFor(() => expect(document.activeElement?.getAttribute("data-chat-index")).toBe("0"));
    expect(document.activeElement?.getAttribute("aria-label")).toContain("안녕하세요");
    expect(document.querySelector("mark.chat-hit")?.textContent).toBe("회의");

    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "ArrowDown" });
    await waitFor(() => expect(document.activeElement?.getAttribute("data-chat-index")).toBe("1"));
    const before = useGridLocalStore.getState().viewerFocusRequests;
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "Enter" });
    const state = useGridLocalStore.getState();
    expect(state.target?.ref.locator).toBe("/artifacts/0");
    expect(state.viewerFocusRequests).toBe(before + 1);

    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "ArrowLeft" });
    expect(document.activeElement?.getAttribute("role")).toBe("option");
  });

  it("reads Teams / Slack desktop messenger rows as conversations (r2 M1)", async () => {
    const teamsSlack = [
      {
        provider: "windows-messenger",
        artifact_type: "chat-message",
        path: "C:/Users/a/AppData/Roaming/Slack/IndexedDB/x.ldb",
        details: {
          service: "Slack",
          conversation_title: "#영업",
          sender: "kim",
          direction: "outgoing",
          message_text_preview: "견적서 보냅니다",
          timestamp: "2026-10-01T01:00:00Z",
        },
      },
      {
        provider: "windows-messenger",
        artifact_type: "chat-message",
        path: "C:/Users/a/AppData/Roaming/Slack/IndexedDB/x.ldb",
        details: {
          service: "Slack",
          conversation_title: "#영업",
          sender: "lee",
          direction: "incoming",
          message_text_preview: "받았습니다",
          timestamp: "2026-10-01T01:05:00Z",
        },
      },
      {
        provider: "windows-messenger",
        artifact_type: "chat-message",
        path: "C:/Users/a/AppData/Local/Packages/MSTeams/EBWebView/x.ldb",
        details: {
          service: "Microsoft Teams (new)",
          conversation_title: "프로젝트 A",
          sender: "park",
          direction: "unknown",
          message_text_preview: "회의 링크",
          timestamp: "2026-10-02T01:00:00Z",
        },
      },
      {
        provider: "windows-messenger",
        artifact_type: "chat-app-inventory",
        path: "C:/Users/a/AppData/Roaming/WeChat",
        details: { service: "WeChat" },
      },
    ];
    const rows = teamsSlack.map((raw, i) =>
      row({
        rowKey: `w${i}`,
        artifactType: raw.artifact_type,
        sourcePath: raw.path,
        fields: { details: raw.details, kind: "windows-messenger" },
      }),
    );
    expect(viewDisabledReason("chat", { id: "artifacts", kind: "windows-messenger" })).toBeUndefined();
    const conversations = groupConversations(rows);
    expect(conversations.map((c) => [c.label, c.service, c.messages.length])).toEqual([
      ["프로젝트 A", "Microsoft Teams (new)", 1],
      ["#영업", "Slack", 2],
    ]);
    expect(conversations[1]?.messages.map((m) => [m.sender, m.outgoing])).toEqual([
      ["kim", true],
      ["lee", false],
    ]);
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, collection: { id: "artifacts", kind: "windows-messenger" } },
    }));
    installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: { "windows-messenger": { artifacts: teamsSlack, total: teamsSlack.length } },
        }),
    });
    renderQ(<ChatView />);
    expect(await screen.findByRole("listbox", { name: /대화 목록, 2개/ })).toBeTruthy();
  });

  it("marks KakaoTalk numeric chat / author ids as unresolved names (m11)", async () => {
    const kakao = [
      {
        provider: "kakaotalk-windows-correlation",
        artifact_type: "kakaotalk-message",
        path: "C:/Users/a/AppData/Local/Kakao/KakaoTalk/users/x/chatLogs_1.edb",
        details: {
          service: "KakaoTalk PC",
          conversation_id: "18291234567",
          sender: "4412345678",
          direction: "수신",
          message_text: "안녕",
          timestamp: "2026-10-01T01:00:00Z",
        },
      },
    ];
    const rows = kakao.map((raw, i) =>
      row({ rowKey: `k${i}`, artifactType: raw.artifact_type, fields: { details: raw.details } }),
    );
    expect(groupConversations(rows)[0]?.label).toBe("18291234567 (이름 미해석)");
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, collection: { id: "artifacts", kind: "kakaotalk-windows" } },
    }));
    installFetch({
      "/artifacts": () =>
        jsonResponse({ artifacts: { "kakaotalk-windows": { artifacts: kakao, total: 1 } } }),
    });
    renderQ(<ChatView />);
    const sender = await screen.findByText(/4412345678 \(이름 미해석\)/);
    expect(sender.getAttribute("title")).toContain("이름을 찾지 못했습니다");
  });

  it("explains a messenger node without message rows", async () => {
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, collection: { id: "artifacts", kind: "kakaotalk-windows" } },
    }));
    installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            "kakaotalk-windows": {
              artifacts: [{ artifact_type: "kakaotalk-windows-source-candidate", path: "C:/x", details: {} }],
              total: 1,
            },
          },
        }),
    });
    renderQ(<ChatView />);
    expect(await screen.findByText("이 노드에는 대화 메시지가 없습니다.")).toBeTruthy();
  });
});

// --- histogram -----------------------------------------------------------------

function payload(buckets: Array<[string, number]>, bucketSeconds: number): TimelineHistogramPayload {
  return {
    total_events: buckets.reduce((s, [, c]) => s + c, 0),
    parsed_events: buckets.reduce((s, [, c]) => s + c, 0),
    unparsed_events: 0,
    bucket_seconds: bucketSeconds,
    bucket_count: buckets.length,
    range_start: buckets[0]?.[0] ?? null,
    range_end: null,
    sources: [],
    buckets: buckets.map(([start, count], index) => ({
      index,
      start,
      end: new Date(Date.parse(start) + bucketSeconds * 1000).toISOString(),
      count,
    })),
  };
}

describe("histogram model", () => {
  it("re-buckets 5-minute server buckets into hour bars with gaps filled", () => {
    const p = payload(
      [
        ["2026-10-01T10:00:00Z", 2],
        ["2026-10-01T10:05:00Z", 3],
        ["2026-10-01T11:10:00Z", 0],
        ["2026-10-01T12:55:00Z", 4],
        ["2026-10-01T13:00:00Z", 0],
      ],
      300,
    );
    const { granularity, buckets } = rebucket(p);
    expect(granularity).toBe("hour");
    expect(buckets.map((b) => b.count)).toEqual([5, 0, 4]);
    expect(new Date(buckets[2]?.startMs ?? 0).toISOString()).toBe("2026-10-01T12:00:00.000Z");
  });

  it("uses day bars for spans over three days and the server buckets for very long spans", () => {
    const days = payload(
      [
        ["2026-10-01T00:00:00Z", 1],
        ["2026-10-01T06:00:00Z", 1],
        ["2026-10-05T18:00:00Z", 2],
      ],
      21600,
    );
    const day = rebucket(days);
    expect(day.granularity).toBe("day");
    expect(day.buckets.map((b) => b.count)).toEqual([2, 0, 0, 0, 2]);
    const years = payload(
      [
        ["2020-01-01T00:00:00Z", 1],
        ["2026-01-01T00:00:00Z", 1],
      ],
      2592000,
    );
    expect(rebucket(years).granularity).toBe("native");
    // A forced finer granularity than the server bucket cannot be split.
    expect(rebucket(years, "hour").granularity).toBe("native");
  });

  it("turns a bar range into an inclusive ISO range in either drag direction", () => {
    const { buckets } = rebucket(
      payload(
        [
          ["2026-10-01T10:00:00Z", 1],
          ["2026-10-01T12:00:00Z", 1],
        ],
        3600,
      ),
    );
    expect(rangeOf(buckets, 2, 0)).toEqual({
      from: "2026-10-01T10:00:00.000Z",
      to: "2026-10-01T12:59:59.999Z",
    });
  });

  it("builds category bars from the run tree and from rows", () => {
    const tree: RunTree = {
      run_id: "r",
      root: {},
      nodes: [
        {
          id: "artifacts",
          label: "아티팩트",
          count: 9,
          collection: "artifacts",
          children: [
            {
              id: "artifacts-group:comm",
              label: "커뮤니케이션",
              count: 9,
              children: [
                {
                  id: "artifacts:mobile-export",
                  label: "모바일",
                  count: 7,
                  kind: "mobile-export",
                  collection: "artifacts",
                  children: [
                    {
                      id: "t1",
                      label: "mobile-app",
                      count: 2,
                      kind: "mobile-export",
                      artifact_type: "mobile-app",
                    },
                    {
                      id: "t2",
                      label: "mobile-message",
                      count: 5,
                      kind: "mobile-export",
                      artifact_type: "mobile-message",
                    },
                  ],
                },
                { id: "artifacts:email", label: "이메일", count: 2, kind: "email", collection: "artifacts" },
              ],
            },
          ],
        },
      ],
    };
    expect(barsFromTree(tree, undefined).map((b) => [b.kind, b.count])).toEqual([
      ["mobile-export", 7],
      ["email", 2],
    ]);
    expect(barsFromTree(tree, "mobile-export").map((b) => [b.artifactType, b.count])).toEqual([
      ["mobile-message", 5],
      ["mobile-app", 2],
    ]);
    const rows = [
      row({ rowKey: "1", sourcePath: "a.PDF" }),
      row({ rowKey: "2", sourcePath: "b.pdf" }),
      row({ rowKey: "3", sourcePath: "c" }),
    ];
    expect(barsFromRows(rows, "files").map((b) => [b.label, b.count])).toEqual([
      [".pdf", 2],
      ["(확장자 없음)", 1],
    ]);
  });
});

describe("HistogramView (timeline)", () => {
  const timeline = payload(
    [
      ["2026-10-01T10:00:00Z", 2],
      ["2026-10-01T11:00:00Z", 6],
      ["2026-10-01T12:00:00Z", 1],
    ],
    3600,
  );

  function captureFilterEvents() {
    const details: unknown[] = [];
    const listener = (event: Event) => details.push((event as CustomEvent).detail);
    window.addEventListener("rapidtriage:filter", listener);
    return { details, off: () => window.removeEventListener("rapidtriage:filter", listener) };
  }

  it("emits rapidtriage:filter for a dragged range and for keyboard selection", async () => {
    useGridLocalStore.setState((s) => ({ route: { ...s.route, collection: { id: "timeline" } } }));
    installFetch({ "/timeline-histogram": () => jsonResponse(timeline) });
    const events = captureFilterEvents();
    renderQ(<HistogramView />);
    const group = await screen.findByRole("group", { name: /타임라인 히스토그램, 막대 3개/ });
    const bars = Array.from(group.querySelectorAll<HTMLButtonElement>("button.hist-bar"));
    expect(bars).toHaveLength(3);
    expect(bars[1]?.getAttribute("aria-label")).toMatch(/6건$/);
    expect(bars.filter((b) => b.tabIndex === 0)).toHaveLength(1);

    fireEvent.mouseDown(bars[0] as HTMLElement, { button: 0 });
    fireEvent.mouseEnter(bars[1] as HTMLElement);
    fireEvent.mouseUp(bars[1] as HTMLElement);
    expect(events.details.at(-1)).toEqual({
      from: "2026-10-01T10:00:00.000Z",
      to: "2026-10-01T11:59:59.999Z",
    });

    act(() => bars[1]?.focus());
    fireEvent.keyDown(bars[1] as HTMLElement, { key: "Escape" }); // clears the dragged range
    expect(bars.some((b) => b.getAttribute("aria-pressed") === "true")).toBe(false);
    fireEvent.keyDown(bars[1] as HTMLElement, { key: "ArrowRight", shiftKey: true });
    expect(document.activeElement).toBe(bars[2]);
    fireEvent.keyDown(bars[2] as HTMLElement, { key: "Enter" });
    expect(events.details.at(-1)).toEqual({
      from: "2026-10-01T11:00:00.000Z",
      to: "2026-10-01T12:59:59.999Z",
    });
    events.off();
  });

  it("shows the descriptive empty state when no event has a usable time", async () => {
    useGridLocalStore.setState((s) => ({ route: { ...s.route, collection: { id: "timeline" } } }));
    installFetch({
      "/timeline-histogram": () =>
        jsonResponse({ ...payload([], 3600), parsed_events: 0, unparsed_events: 4 }),
    });
    renderQ(<HistogramView />);
    expect(await screen.findByText("플롯할 타임라인 데이터가 없습니다.")).toBeTruthy();
    expect(screen.getByText(/시각을 해석할 수 없는 이벤트 4건/)).toBeTruthy();
  });
});
