import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveRegion } from "../../a11y";
import { resetAnnouncer } from "../../a11y/announcer";
import type { GridRow } from "../../contracts/collection";
import type { CommandContext } from "../../contracts/command";
import {
  getCommand,
  getViewerTarget,
  registerCommand,
  requestViewerFocus,
  resetViewerAdapter,
  setViewerRouteMode,
  setViewerTarget,
  useViewerRouteMode,
} from "./adapter";
import { clearCaseDbCache } from "./citation";
import { type Handler, installFetch, jsonResponse, metadata, preview, target } from "./testSupport";
import { Viewer } from "./Viewer";

const SHA = "a".repeat(64);
let clipboard: string[];

beforeEach(() => {
  resetAnnouncer();
  URL.createObjectURL = vi.fn(() => "blob:mock");
  URL.revokeObjectURL = vi.fn();
  resetViewerAdapter();
  clearCaseDbCache();
  clipboard = [];
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn(async (text: string) => void clipboard.push(text)) },
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const ctx = (hasTarget: boolean): CommandContext => ({
  runId: hasTarget ? "run-1" : null,
  collection: null,
  selectedRowKeys: [],
  focusedRowKey: null,
  viewerHasTarget: hasTarget,
  runIsActive: false,
});

function routes(previewBody: unknown, extra: Record<string, Handler> = {}) {
  return installFetch({
    "source-preview": () => previewBody,
    "source-metadata": (url) =>
      metadata(url.searchParams.get("path") || "", 64, url.searchParams.get("hash") ? SHA : undefined),
    "source-hex-range": () => ({ offset: 0, rows: [], length_returned: 0, size: 64 }),
    ...extra,
  });
}

const region = () => screen.getByRole("region", { name: "원본 뷰어" });
const tab = (name: string) => screen.getByRole("tab", { name });
const live = () => (screen.getByTestId("live-polite").textContent ?? "").trim();
/** Menu holding each viewer command (review #6): the ⋯ 더보기 menu (marks: the status chip menu). */
const MENU_OF: Record<string, string> = {
  "viewer.open-original": "더보기",
  "viewer.hash": "더보기",
  "viewer.copy-path": "더보기",
  "viewer.cite": "더보기",
  "navigate.rows-for-source": "더보기",
  "viewer.note": "더보기",
};
/** The control of a viewer command, opening the menu that holds it first. */
const tool = (id: string) => {
  const selector = `[data-command="${id}"]`;
  const shown = document.querySelector(selector);
  if (shown) return shown as HTMLButtonElement;
  // Every mark lives in the one review-status chip menu (r7 L4, C-W9).
  if (id.startsWith("viewer.mark.")) fireEvent.click(screen.getByTestId("viewer-review-status-menu"));
  const menu = MENU_OF[id];
  if (menu) fireEvent.click(screen.getByRole("button", { name: menu }));
  return document.querySelector(selector) as HTMLButtonElement;
};

async function show(
  previewBody: Record<string, unknown>,
  overrides = {},
  extra: Record<string, Handler> = {},
) {
  const calls = routes(preview(previewBody), extra);
  render(
    <>
      <Viewer />
      <LiveRegion />
    </>,
  );
  act(() => setViewerTarget(target(overrides)));
  await waitFor(() => expect(live()).toContain("원본 로드됨"));
  return calls;
}

describe("Viewer — empty state and toolbar", () => {
  it("shows one sentence with the Enter hint and disables every toolbar command with a reason", () => {
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    expect(screen.getByText(/행을 선택하면 원본이 여기에 표시됩니다/).textContent).toContain("Enter");
    for (const id of ["viewer.open-original", "viewer.hash", "viewer.copy-path", "viewer.cite"]) {
      expect(tool(id).getAttribute("aria-disabled")).toBe("true");
      expect(tool(id).getAttribute("data-disabled-reason")).toBe("뷰어에 표시된 행이 없습니다.");
    }
    expect(tool("viewer.mark.relevant").getAttribute("aria-disabled")).toBe("true");
    expect(screen.getAllByRole("tab").every((t) => t.getAttribute("aria-disabled") === "true")).toBe(true);
  });

  it("registers the toolbar actions as commands that report disabledReason", async () => {
    routes(preview({ preview_type: "text", extension: ".txt", text: "hello" }));
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    for (const id of [
      "viewer.open-original",
      "viewer.hash",
      "viewer.copy-path",
      "viewer.cite",
      "viewer.mark.relevant",
      "viewer.mark.needs-review",
      "viewer.mark.excluded",
      "viewer.mark.include-in-report",
      "viewer.mark.bookmark",
      "viewer.back",
      "viewer.forward",
    ]) {
      expect(getCommand(id), id).toBeDefined();
    }
    expect(getCommand("viewer.copy-path")?.disabledReason?.(ctx(false))).toBe("뷰어에 표시된 행이 없습니다.");
    act(() => setViewerTarget(target()));
    expect(getCommand("viewer.copy-path")?.disabledReason?.(ctx(true))).toBeUndefined();
    expect(getCommand("viewer.mark.relevant")?.disabledReason?.(ctx(true))).toBeUndefined();
    act(() => setViewerTarget(target({ sourcePath: null })));
    expect(getCommand("viewer.open-original")?.disabledReason?.(ctx(true))).toContain(
      "원본 파일 경로가 없는",
    );
    expect(getCommand("viewer.cite")?.disabledReason?.(ctx(true))).toBeUndefined();
  });

  it("a disabled command exposes its reason only through the tooltip (aria-describedby)", () => {
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    const button = tool("viewer.copy-path");
    fireEvent.click(button);
    expect(clipboard).toEqual([]);
    const tip = document.getElementById(button.getAttribute("aria-describedby") || "");
    // Description persists but is `hidden` (not page text); the visible tooltip mounts on hover/focus.
    expect(tip?.hasAttribute("hidden")).toBe(true);
    expect(tip?.textContent).toBe("뷰어에 표시된 행이 없습니다.");
  });
});

describe("Viewer — loading, modes, focus", () => {
  it("sets aria-busy while loading and announces one sentence when done", async () => {
    let release: (value: Response) => void = () => undefined;
    installFetch({
      "source-preview": () => new Promise<Response>((resolve) => (release = resolve)),
      "source-metadata": () => metadata("C:/evidence/file.bin", 64),
    });
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    act(() => setViewerTarget(target()));
    expect(region().getAttribute("aria-busy")).toBe("true");
    expect(screen.getByText("원본을 불러오는 중…")).toBeTruthy();
    await act(async () =>
      release(jsonResponse(preview({ name: "notes.txt", preview_type: "text", text: "x" }))),
    );
    await waitFor(() => expect(region().getAttribute("aria-busy")).toBe("false"));
    await waitFor(() => expect(live()).toBe("원본 로드됨: notes.txt"));
  });

  it.each([
    [{ preview_type: "text", extension: ".log", text: "line" }, "원본"],
    [{ preview_type: "text", extension: ".pdf", text: "추출 본문" }, "문서"],
    [{ preview_type: "json", extension: ".json", text: "{}", json: { item_count: 1 } }, "원본"],
    [{ preview_type: "xml", extension: ".xml", text: "<a/>", xml: { root_tag: "a", nodes: [] } }, "원본"],
    [{ preview_type: "image", extension: ".png", image: {} }, "이미지"],
    [{ preview_type: "sqlite", extension: ".db", sqlite: { tables: [] } }, "SQLite"],
    [{ preview_type: "email", extension: ".eml", email: { messages: [] } }, "이메일"],
    [{ preview_type: "media", extension: ".wav", size: 10, media: {} }, "미디어"],
    [{ preview_type: "hex", extension: ".evtx" }, "헥스"],
    [{ preview_type: "binary", extension: ".dat" }, "헥스"],
  ])("auto-selects the mode for %o", async (body, expected) => {
    await show(
      body,
      {},
      {
        "source-image-gallery": () => ({
          offset: 0,
          limit: 12,
          returned: 0,
          total: 0,
          has_next: false,
          items: [],
        }),
        "source-file": () => new Response("x"),
      },
    );
    expect(tab(expected).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("tabpanel").getAttribute("aria-labelledby")).toBe(tab(expected).id);
  });

  it("wires every tab to its own tabpanel (labelled by that tab); only the active panel is shown", async () => {
    await show({ preview_type: "text", extension: ".txt", text: "hi" });
    const tabs = screen.getAllByRole("tab");
    expect(tabs.length).toBeGreaterThan(1);
    for (const t of tabs) {
      expect(t.id).toBe(`viewer-tab-${t.dataset.mode}`);
      const panel = document.getElementById(t.getAttribute("aria-controls") || "");
      expect(panel?.getAttribute("role")).toBe("tabpanel");
      expect(panel?.getAttribute("aria-labelledby")).toBe(t.id);
      const selected = t.getAttribute("aria-selected") === "true";
      expect(panel?.hidden).toBe(!selected);
      if (!selected) expect(panel?.childElementCount).toBe(0);
    }
    expect(screen.getAllByRole("tabpanel")).toHaveLength(1);
  });

  it("renders disabled tabs with a Korean reason in the tooltip only — never in the panel body", async () => {
    await show({ preview_type: "text", extension: ".txt", text: "hi" });
    const sqlite = tab("SQLite");
    expect(sqlite.getAttribute("aria-disabled")).toBe("true");
    const described = document.getElementById(sqlite.getAttribute("aria-describedby") || "");
    expect(described?.hasAttribute("hidden")).toBe(true);
    expect(described?.textContent).toBe("SQLite 데이터베이스가 아닙니다.");
    fireEvent.click(sqlite);
    expect(sqlite.getAttribute("aria-selected")).toBe("false");
    const panel = screen.getByRole("tabpanel");
    for (const reason of [
      "SQLite 데이터베이스가 아닙니다.",
      "이미지 파일이 아닙니다.",
      "오디오·비디오 파일이 아닙니다.",
    ]) {
      expect(panel.textContent).not.toContain(reason);
    }
    // Only the hidden description / on-hover tooltip carry reasons; no visible text node has them.
    const holders = Array.from(document.querySelectorAll("*")).filter(
      (el) => el.children.length === 0 && el.textContent === "이미지 파일이 아닙니다.",
    );
    expect(holders.length).toBeGreaterThan(0);
    expect(holders.every((el) => el.hasAttribute("hidden") || el.getAttribute("role") === "tooltip")).toBe(
      true,
    );
  });

  it("uses no banner landmark and no local live region (S5 announcer only)", async () => {
    await show({ preview_type: "text", extension: ".txt", text: "hi" });
    expect(region().querySelector("header")).toBeNull();
    expect(region().querySelector("[aria-live], [role=status], [role=alert]")).toBeNull();
    expect(screen.getByRole("heading", { level: 2 }).textContent).toBe("file.bin");
  });

  it("moves between tabs with arrow keys (disabled tabs focus but do not activate)", async () => {
    await show({ preview_type: "text", extension: ".txt", text: "hi" });
    tab("원본").focus();
    fireEvent.keyDown(tab("원본"), { key: "ArrowRight" });
    expect(document.activeElement).toBe(tab("헥스"));
    expect(tab("헥스").getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(tab("헥스"), { key: "ArrowRight" });
    expect(document.activeElement).toBe(tab("SQLite"));
    expect(tab("헥스").getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(tab("SQLite"), { key: "End" });
    // The last tab is 계열 (R7 갈래 A), available on a files row.
    expect(document.activeElement).toBe(tab("계열"));
    expect(tab("계열").getAttribute("aria-selected")).toBe("true");
  });

  it("moves focus to the selected mode tab when opened with Enter (requestViewerFocus)", async () => {
    routes(preview({ preview_type: "sqlite", extension: ".db", sqlite: { tables: [] } }));
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    act(() => {
      setViewerTarget(target());
      requestViewerFocus();
    });
    await waitFor(() => expect(document.activeElement).toBe(tab("SQLite")));
  });

  it("restores the URL mode= tab, mirrors tab choices back, and marks the selected tab for S1's focusViewer", async () => {
    routes(preview({ preview_type: "text", extension: ".txt", text: "hi" }));
    let routeMode: string | undefined;
    function Probe() {
      routeMode = useViewerRouteMode().mode;
      return null;
    }
    act(() => {
      setViewerRouteMode("hex");
      setViewerTarget(target());
    });
    render(
      <>
        <Viewer />
        <LiveRegion />
        <Probe />
      </>,
    );
    await waitFor(() => expect(live()).toContain("원본 로드됨"));
    expect(tab("헥스").getAttribute("aria-selected")).toBe("true");
    expect(document.querySelector("[data-viewer-focus]")).toBe(tab("헥스"));
    fireEvent.click(tab("메타"));
    expect(routeMode).toBe("meta");
    act(() => setViewerTarget(target({ ref: { collection: "files", locator: "/candidates/8" } })));
    await waitFor(() => expect(tab("원본").getAttribute("aria-selected")).toBe("true"));
    expect(routeMode).toBeUndefined();
  });

  it("does not steal focus on a plain selection change", async () => {
    await show({ preview_type: "text", extension: ".txt", text: "hi" });
    expect(document.activeElement).toBe(document.body);
  });

  it("highlights route keywords in document text", async () => {
    window.location.hash = "#/case/run-1/explore/docs?q=계약";
    await show({ preview_type: "text", extension: ".pdf", text: "이 계약은 무효\n다른 줄" });
    const hits = document.querySelectorAll("mark.viewer-hit");
    expect(Array.from(hits).map((h) => h.textContent)).toEqual(["계약"]);
    window.location.hash = "";
  });

  it("rows without a source file show metadata only", async () => {
    routes(preview({}));
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    act(() =>
      setViewerTarget(
        target({ sourcePath: null, ref: { collection: "indicators", locator: "/indicators/2" } }),
      ),
    );
    expect(tab("메타").getAttribute("aria-selected")).toBe("true");
    await waitFor(() => expect(live()).toContain("원본 파일이 없는 행입니다"));
    expect(screen.getByText("원본 경로 없음(파생 항목)")).toBeTruthy();
  });
});

describe("Viewer — toolbar actions", () => {
  it("copies the path and the hash", async () => {
    await show({ preview_type: "text", extension: ".txt", text: "hi" });
    fireEvent.click(tool("viewer.copy-path"));
    await waitFor(() => expect(clipboard).toEqual(["C:/evidence/file.bin"]));
    await waitFor(() => expect(live()).toBe("경로를 복사했습니다."));
    fireEvent.click(tool("viewer.hash"));
    await waitFor(() => expect(clipboard[1]).toBe(SHA));
  });

  it("copies a one-line citation with path, sha256, locator and run id", async () => {
    const calls = await show({ preview_type: "text", extension: ".txt", text: "hi" });
    fireEvent.click(tool("viewer.cite"));
    await waitFor(() => expect(clipboard).toHaveLength(1));
    expect(clipboard[0]).toBe(`원본=C:/evidence/file.bin; sha256=${SHA}; 위치=files:/candidates/7; 런=run-1`);
    expect(
      calls.some((c) => c.url.pathname.endsWith("source-metadata") && c.url.searchParams.get("hash")),
    ).toBe(true);
  });

  it("marks through the case DB with the run locator when the row has no case-db id", async () => {
    const calls = await show(
      { preview_type: "text", extension: ".txt", text: "hi" },
      {},
      {
        ensure: () => ({ database: "D:/out/rapidtriage-case.db", case_id: "run-out" }),
        "review-batch": () => ({ ok: true }),
      },
    );
    fireEvent.click(tool("viewer.mark.relevant"));
    await waitFor(() => expect(live()).toBe("표시됨: 관련 있음"));
    const post = calls.find((c) => c.url.pathname === "/api/case-db/review-batch");
    expect(post?.init?.method).toBe("POST");
    expect(JSON.parse(String(post?.init?.body))).toEqual({
      database: "D:/out/rapidtriage-case.db",
      case_id: "run-out",
      run_id: "run-1",
      targets: [{ collection: "files", locator: "/candidates/7" }],
      reviewer: "web-ui",
      status: "relevant",
    });
    fireEvent.click(tool("viewer.mark.include-in-report"));
    await waitFor(() => expect(live()).toBe("표시됨: 보고서 포함"));
    const last = calls.filter((c) => c.url.pathname.endsWith("review-batch")).at(-1);
    expect(JSON.parse(String(last?.init?.body))).toMatchObject({ include_in_report: true });
    expect(calls.filter((c) => c.url.pathname.endsWith("ensure"))).toHaveLength(1); // once per run
  });

  it("falls back to the case.json bookmark only when no case DB can be created, and says so", async () => {
    const calls = await show(
      { preview_type: "text", extension: ".txt", text: "hi" },
      {},
      {
        ensure: () => jsonResponse({ detail: "case DB unavailable" }, 400),
        bookmarks: () => ({ ok: true }),
      },
    );
    fireEvent.click(tool("viewer.mark.relevant"));
    await waitFor(() => expect(live()).toContain("case.json 북마크에 저장했습니다"));
    const post = calls.find((c) => c.url.pathname === "/api/runs/run-1/bookmarks");
    expect(JSON.parse(String(post?.init?.body))).toEqual({
      source: "files",
      pointer: "/candidates/7",
      review_status: "relevant",
    });
  });

  it("marks persisted rows through the shared review implementation (POST /api/case-db/review-batch)", async () => {
    const calls = await show(
      { preview_type: "text", extension: ".txt", text: "hi" },
      {
        ref: { collection: "artifacts", kind: "eventlog", locator: "artifacts_eventlog:row:3", caseDbId: 42 },
      },
      {
        ensure: () => ({ database: "D:/case.db", case_id: "run-run-1" }),
        "review-batch": () => ({ ok: true }),
      },
    );
    fireEvent.click(tool("viewer.mark.excluded"));
    await waitFor(() => expect(live()).toBe("표시됨: 제외"));
    const review = calls.find((c) => c.url.pathname === "/api/case-db/review-batch");
    expect(JSON.parse(String(review?.init?.body))).toEqual({
      database: "D:/case.db",
      case_id: "run-run-1",
      run_id: "run-1",
      targets: [{ target_type: "artifact", target_id: "42" }],
      reviewer: "web-ui",
      status: "excluded",
      include_in_report: false,
    });
  });

  it("reports API failures in the live region", async () => {
    await show(
      { preview_type: "text", extension: ".txt", text: "hi" },
      {},
      {
        ensure: () => ({ database: "D:/case.db", case_id: "run-run-1" }),
        "review-batch": () => jsonResponse({ detail: "case DB has no row for run locator(s)" }, 400),
      },
    );
    fireEvent.click(tool("viewer.mark.bookmark"));
    await waitFor(() => expect(live()).toBe("표시 실패: case DB has no row for run locator(s)"));
  });

  it("R-1: a failed mark (403) rolls the status chip back to the previous status", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    await show(
      { preview_type: "text", extension: ".txt", text: "hi" },
      {},
      {
        ensure: () => ({ database: "D:/case.db", case_id: "run-run-1" }),
        "review-batch": async () => {
          await gate;
          return jsonResponse({ detail: "쓰기 차단" }, 403);
        },
      },
    );
    const chip = () => screen.getByTestId("viewer-review-status");
    expect(chip().textContent).toBe("미검토");
    fireEvent.click(tool("viewer.mark.relevant"));
    // Optimistic while the request is in flight …
    await waitFor(() => expect(chip().textContent).toBe("관련 있음"));
    release();
    // … and back to 미검토 once the server refuses it, with the failure toast.
    await waitFor(() => expect(live()).toBe("표시 실패: 쓰기 차단"));
    await waitFor(() => expect(chip().textContent).toBe("미검토"));
  });
});

describe("Viewer — history and navigation", () => {
  it("Alt+← / Alt+→ walk previously shown targets", async () => {
    routes(preview({ preview_type: "text", extension: ".txt", text: "hi" }));
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    act(() => setViewerTarget(target({ ref: { collection: "files", locator: "/candidates/1" } })));
    act(() => setViewerTarget(target({ ref: { collection: "files", locator: "/candidates/2" } })));
    fireEvent.keyDown(region(), { key: "ArrowLeft", altKey: true });
    expect(getViewerTarget()?.ref.locator).toBe("/candidates/1");
    fireEvent.keyDown(region(), { key: "ArrowRight", altKey: true });
    expect(getViewerTarget()?.ref.locator).toBe("/candidates/2");
    await waitFor(() => expect(live()).toBe("원본 로드됨: file.bin"));
    fireEvent.keyDown(region(), { key: "ArrowRight", altKey: true });
    await waitFor(() => expect(live()).toBe("다음 대상이 없습니다."));
  });

  it("keeps Alt+←/→ history and the chosen tab across a remount (stage switch, review B2-3)", async () => {
    routes(preview({ preview_type: "text", extension: ".txt", text: "hi" }));
    const first = render(<Viewer />);
    act(() => setViewerTarget(target({ ref: { collection: "files", locator: "/candidates/1" } })));
    act(() => setViewerTarget(target({ ref: { collection: "files", locator: "/candidates/2" } })));
    await waitFor(() => expect(screen.getByRole("tab", { name: /헥스/ })).toBeTruthy());
    fireEvent.click(screen.getByRole("tab", { name: /헥스/ }));
    expect(screen.getByRole("tab", { name: /헥스/ }).getAttribute("aria-selected")).toBe("true");
    first.unmount(); // 탐색 → 처리 (two columns, no viewer)
    render(<Viewer />); // … and back to 탐색
    await waitFor(() =>
      expect(screen.getByRole("tab", { name: /헥스/ }).getAttribute("aria-selected")).toBe("true"),
    );
    fireEvent.keyDown(region(), { key: "ArrowLeft", altKey: true });
    expect(getViewerTarget()?.ref.locator).toBe("/candidates/1");
  });

  it("'같은 출처의 다른 행' emits navigate.rows-for-source when a handler is registered", async () => {
    await show({ preview_type: "text", extension: ".txt", text: "hi" });
    // It lives in the one "⋯" 더보기 menu (review #6).
    fireEvent.click(screen.getByRole("button", { name: "더보기" }));
    const button = screen.getByRole("menuitem", { name: "같은 출처의 다른 행" });
    expect(button.getAttribute("aria-disabled")).toBe("true");
    const run = vi.fn();
    const events: unknown[] = [];
    window.addEventListener("rapidtriage:command", (event) => events.push((event as CustomEvent).detail));
    act(() => {
      registerCommand({ id: "navigate.rows-for-source", label: "같은 출처 행", group: "navigate", run });
    });
    const enabled = screen.getByRole("menuitem", { name: "같은 출처의 다른 행" });
    expect(enabled.getAttribute("aria-disabled")).toBeNull();
    fireEvent.click(enabled);
    await waitFor(() => expect(run).toHaveBeenCalledTimes(1));
    expect(events).toEqual([{ id: "navigate.rows-for-source", target: getViewerTarget() }]);
  });
});

const EVTX_ROW: GridRow = {
  rowKey: "artifacts:/artifacts/1",
  ref: { collection: "artifacts", kind: "eventlog", locator: "/artifacts/1" },
  title: "1531",
  sourcePath: "C:/evidence/Application.evtx",
  timestamp: "2025-02-23T13:47:11.774458+00:00",
  artifactType: "eventlog-event",
  provider: "windows-eventlog",
  sha256: null,
  reviewStatus: null,
  tags: [],
  fields: {
    kind: "eventlog",
    details: {
      timestamp: "2025-02-23T13:47:11.774458+00:00",
      event_id: "1531",
      record_id: "1",
      provider_name: "Microsoft-Windows-User Profiles Service",
      computer: "진료실1",
      event_tags: ["category:event", "channel:application"],
      event_message: "provider=Microsoft-Windows-User Profiles Service | channel=Application",
      evtx_record_offset: 4608,
      evtx_record_size: 1568,
      evtx_record_sha256: "c79f",
      caution_labels: ["binxml-not-decoded"],
      evtx_binxml_status: 0,
      thread_id: "1680",
      event_data_values: ["0c01"],
    },
  },
};

describe("Viewer — decoded artifact rows (F2)", () => {
  const artifactTarget = () => target({ ref: EVTX_ROW.ref, sourcePath: "C:/evidence/Application.evtx" });

  it("prefers 메타 and renders the decoded record first, grouped", async () => {
    routes(preview({ preview_type: "hex", extension: ".evtx", size: 13_000_000, name: "Application.evtx" }));
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    act(() => setViewerTarget(artifactTarget(), EVTX_ROW));
    expect(tab("메타").getAttribute("aria-selected")).toBe("true");
    await waitFor(() => expect(live()).toContain("원본 로드됨"));
    expect(tab("메타").getAttribute("aria-selected")).toBe("true");
    const panel = screen.getByRole("tabpanel");
    const firstHeading = panel.querySelector("h3");
    expect(firstHeading?.textContent).toMatch(/^레코드 · 이벤트 로그/);
    // Banners first: the parser's caution label is a warning above the fields.
    const banners = screen.getByTestId("record-banners");
    expect(banners.textContent).toContain("파서 주의 표시");
    expect(
      banners.compareDocumentPosition(firstHeading as Node) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    const core = screen.getByRole("region", { name: "레코드 핵심" });
    const terms = Array.from(core.querySelectorAll("dt"));
    // Event Log field sheet order (AXIOM-style): 이벤트 ID · 제공자 · 채널 · 컴퓨터 … 레코드 ID.
    const keys = terms.map((dt) => dt.getAttribute("data-key"));
    expect(keys.slice(0, 4)).toEqual(["event_id", "provider_name", "channel", "computer"]);
    expect(keys).toContain("record_id");
    expect(keys.indexOf("record_id")).toBeGreaterThan(keys.indexOf("computer"));
    expect(terms.slice(0, 4).map((dt) => dt.textContent)).toEqual(["이벤트 ID", "제공자", "채널", "컴퓨터"]);
    expect(terms[0]?.getAttribute("title")).toContain("event_id");
    expect(core.textContent).toContain("application");
    const source = screen.getByRole("region", { name: "레코드 출처" });
    expect(source.textContent).toContain("EVTX 레코드 오프셋4608");
    expect(source.textContent).toContain("EVTX 레코드 SHA-256");
    // No "검증" group above the evidence any more; labelled extra keys are visible (추가 필드).
    expect(screen.queryByRole("region", { name: "레코드 검증" })).toBeNull();
    const other = screen.getByRole("region", { name: "레코드 추가 필드" });
    expect(other.textContent).toContain("이벤트 데이터");
  });

  it("opens hex at the record offset with the record range highlighted", async () => {
    const calls = routes(
      preview({ preview_type: "hex", extension: ".evtx", size: 13_000_000, name: "Application.evtx" }),
      {
        "source-hex-range": (url) => {
          const offset = Number(url.searchParams.get("offset"));
          const length = Number(url.searchParams.get("length"));
          return { offset, rows: hexRowsFor(offset, length), length_returned: length, size: 13_000_000 };
        },
      },
    );
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    act(() => setViewerTarget(artifactTarget(), EVTX_ROW));
    await waitFor(() => expect(live()).toContain("원본 로드됨"));
    fireEvent.click(tab("헥스"));
    await screen.findByRole("grid");
    expect(document.getElementById(`hex-row-${4608 / 16}`)?.tabIndex).toBe(0);
    await waitFor(() => expect(document.querySelectorAll(".hex-byte.is-hl").length).toBeGreaterThan(0));
    expect(
      calls.some(
        (c) => c.url.pathname.endsWith("source-hex-range") && c.url.searchParams.get("offset") === "4096",
      ),
    ).toBe(true);
    expect(
      calls.some(
        (c) => c.url.pathname.endsWith("source-hex-range") && c.url.searchParams.get("offset") === "0",
      ),
    ).toBe(false);
    expect(screen.getByText(/커서 0x00001200/)).toBeTruthy();
  });

  it("cites the record byte range", async () => {
    routes(preview({ preview_type: "hex", extension: ".evtx", size: 13_000_000, name: "Application.evtx" }));
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    act(() => setViewerTarget(artifactTarget(), EVTX_ROW));
    await waitFor(() => expect(live()).toContain("원본 로드됨"));
    fireEvent.click(tool("viewer.cite"));
    await waitFor(() => expect(clipboard).toHaveLength(1));
    expect(clipboard[0]).toContain("위치=artifacts:eventlog:/artifacts/1");
    expect(clipboard[0]).toContain("바이트=0x00001200-0x0000181f");
  });

  it("keeps the row context when a bridge re-publishes the same target without a row", () => {
    routes(preview({}));
    act(() => setViewerTarget(artifactTarget(), EVTX_ROW));
    act(() => setViewerTarget({ ...artifactTarget() }));
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    expect(screen.getByRole("region", { name: "레코드 핵심" })).toBeTruthy();
  });
});

function hexRowsFor(offset: number, length: number) {
  const rows = [];
  for (let rel = 0; rel < length; rel += 16) {
    const bytes = Array.from({ length: Math.min(16, length - rel) }, (_, i) => (offset + rel + i) & 0xff);
    rows.push({
      offset: offset + rel,
      offset_hex: "",
      hex: bytes.map((b) => b.toString(16).padStart(2, "0")).join(" "),
      ascii: "",
    });
  }
  return rows;
}

describe("특이사항 banner per row (review #11)", () => {
  it("collapsing one row's banner does not keep the next row's A banner collapsed", async () => {
    routes(preview({ preview_type: "text", text: "x" }));
    const flagged = (locator: string): GridRow =>
      ({
        rowKey: `artifacts:k:${locator}`,
        ref: { collection: "artifacts", kind: "k", locator },
        title: locator,
        sourcePath: null,
        timestamp: null,
        tags: [],
        reviewStatus: null,
        fields: { flags: [{ id: "eventlog.log_cleared", grade: "A", label: "로그 삭제" }] },
      }) as unknown as GridRow;
    const a = flagged("/artifacts/1");
    const b = flagged("/artifacts/2");
    render(<Viewer />);
    act(() => setViewerTarget({ runId: "run-1", ref: a.ref, sourcePath: null }, a));
    const first = (await screen.findByTestId("viewer-flag-banner")) as HTMLDetailsElement;
    expect(first.open).toBe(true);
    act(() => {
      first.open = false;
      first.dispatchEvent(new Event("toggle"));
    });
    act(() => setViewerTarget({ runId: "run-1", ref: b.ref, sourcePath: null }, b));
    await waitFor(() =>
      expect((screen.getByTestId("viewer-flag-banner") as HTMLDetailsElement).open).toBe(true),
    );
  });
});
