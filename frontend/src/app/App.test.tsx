import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { resetAppStore, useAppStore } from "../state/store";
import { App } from "./App";
import { registerAppSlots } from "./registerSlots";

beforeAll(() => {
  // jsdom lacks ResizeObserver (react-resizable-panels).
  if (!("ResizeObserver" in window)) {
    class RO {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
    Object.assign(window, { ResizeObserver: RO });
    Object.assign(globalThis, { ResizeObserver: RO });
  }
  registerAppSlots();
});

beforeEach(() => {
  window.history.replaceState(null, "", "/v2/");
  resetAppStore({ route: { runId: null, collection: null } });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const run = {
        run_id: "run-aaaaaaaa",
        status: "running",
        created_at: new Date().toISOString(),
        request: { root: "D:/evidence/case1.E01", mode: "hacking" },
        progress: {
          stage: "artifacts",
          completed_count: 3,
          total_count: 8,
          error_count: 1,
          running: ["evtx"],
        },
      };
      const path = String(url).split("?")[0] ?? "";
      const body =
        path === "/api/runs"
          ? { runs: [run] }
          : path === "/api/runs/run-aaaaaaaa"
            ? {
                ...run,
                progress: {
                  status: "running",
                  stage: "artifacts",
                  completed_stages: [{ stage: "inventory", completed_at: new Date().toISOString() }],
                  providers: {
                    evtx: { status: "running" },
                    registry: { status: "completed", duration_ms: 1200 },
                  },
                  completed_count: 3,
                  total_count: 8,
                  error_count: 1,
                },
              }
            : path.endsWith("/review-counts") || path.includes("case-db/review")
              ? { by_status: {}, report_candidates: 0 }
              : path.endsWith("/output-files")
                ? {
                    files: [
                      { name: "summary.json", path: "D:/out/summary.json", size: 2048, download_url: "/x" },
                    ],
                  }
                : {};
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderApp() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>,
  );
}

describe("App shell", () => {
  it("renders the landmarks, skip link and live status bar", async () => {
    renderApp();
    act(() => useAppStore.getState().navigate({ runId: "run-aaaaaaaa", collection: "files" }));
    // The top bar is the page banner (feature <header>s live inside sectioning elements).
    const topbar = screen.getByTestId("topbar");
    expect(topbar.tagName).toBe("HEADER");
    expect(topbar.closest("article, aside, main, nav, section")).toBeNull();
    expect(screen.getByRole("navigation", { name: "탐색 트리" })).toBeTruthy();
    const main = screen.getByRole("main");
    expect(main.id).toBe("main");
    expect(main.getAttribute("tabindex")).toBe("-1");
    expect(screen.getByRole("complementary", { name: "뷰어 패널" })).toBeTruthy();
    expect(screen.getByRole("contentinfo")).toBeTruthy();
    expect(document.querySelector("a.skip-link")).toBeTruthy();
    await waitFor(() => expect(screen.getByTestId("status-connection").textContent).toBe("연결됨"));
  });

  it("top bar: brand mark, case, search with its options inside, ⌘K, then only theme + help (S7)", () => {
    renderApp();
    const topbar = screen.getByTestId("topbar");
    expect(topbar.querySelector(".brand .brand-mark")).toBeTruthy();
    expect(topbar.textContent).toContain("RapidForensic");
    // Search options are folded into the search field.
    const search = topbar.querySelector(".global-search") as HTMLElement;
    expect(search.querySelector('[aria-label="검색 옵션"]')).toBeTruthy();
    expect(screen.getByTestId("palette-button").getAttribute("aria-keyshortcuts")).toBe("Control+K");
    const actions = topbar.querySelector(".topbar-actions") as HTMLElement;
    expect(Array.from(actions.querySelectorAll("button")).map((b) => b.dataset.testid)).toEqual([
      "theme-toggle",
      "help-button",
    ]);
    // 리뷰보드 / 보고 are rail stages; density lives in the grid's column menu.
    for (const gone of ["review-board-button", "report-button", "density-toggle"])
      expect(screen.queryByTestId(gone)).toBeNull();
  });

  it("without a case the body is the landing card: start actions and recent cases (S10)", async () => {
    renderApp();
    const landing = screen.getByTestId("landing");
    expect(screen.getByRole("main").contains(landing)).toBe(true);
    expect(screen.queryByRole("navigation", { name: "탐색 트리" })).toBeNull();
    expect(screen.queryByRole("complementary", { name: "뷰어 패널" })).toBeNull();
    expect(screen.getByRole("heading", { level: 1, name: "RapidForensic" })).toBeTruthy();
    for (const name of ["케이스 열기", "이미지 실행", "샘플"])
      expect(screen.getByRole("button", { name })).toBeTruthy();
    const recent = await screen.findByRole("link", { name: /case1\.E01/ });
    expect(recent.getAttribute("href")).toBe("#/case/run-aaaaaaaa/intake");
  });

  it("접수 · 처리 · 보고 are two columns; the viewer appears on 탐색 · 검토 only (S9)", () => {
    renderApp();
    const shell = screen.getByTestId("workbench-shell");
    for (const [collection, columns] of [
      ["intake", "two"],
      ["process", "two"],
      ["outputs", "two"],
      ["files", "three"],
      ["review", "three"],
    ] as const) {
      act(() => useAppStore.getState().navigate({ runId: "run-aaaaaaaa", collection }));
      expect(shell.getAttribute("data-columns"), collection).toBe(columns);
      const viewer = screen.queryByRole("complementary", { name: "뷰어 패널" });
      expect(Boolean(viewer), collection).toBe(columns === "three");
      expect(screen.getByTestId("tree-region")).toBeTruthy();
    }
  });

  it("routes from the case picker and shows run progress with cancel/retry state", async () => {
    renderApp();
    const picker = (await screen.findByTestId("case-picker")) as HTMLSelectElement;
    await waitFor(() => expect(picker.options.length).toBe(2));
    fireEvent.change(picker, { target: { value: "run-aaaaaaaa" } });
    expect(window.location.hash).toBe("#/case/run-aaaaaaaa/intake");
    const status = await screen.findByTestId("status-run");
    expect(status.textContent).toContain("provider 3/8");
    expect(status.textContent).toContain("오류 1");
    expect(screen.getByTestId("run-retry").getAttribute("aria-disabled")).toBe("true");
    expect(screen.getByTestId("run-cancel").getAttribute("aria-disabled")).toBeNull();
    // 접수 dashboard (S7) replaces the grid on the intake node.
    await waitFor(() => expect(screen.getByTestId("intake-pane").textContent).toContain("registry"));
    const intake = screen.getByTestId("intake-pane");
    expect(intake.textContent).toContain("inventory");
    expect(intake.textContent).toContain("케이스 처리 세부");
    expect(intake.textContent).toContain("런이 완료되면 표시됩니다.");
  });

  it("Ctrl K opens the palette and ? opens help through the single key map", async () => {
    renderApp();
    await act(async () => {
      fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    });
    expect(useAppStore.getState().paletteOpen).toBe(true);
    expect(screen.getByRole("dialog")).toBeTruthy();
    fireEvent.keyDown(screen.getByRole("combobox", { name: "명령 또는 검색어" }), { key: "Escape" });
    expect(useAppStore.getState().paletteOpen).toBe(false);
    await act(async () => {
      fireEvent.keyDown(document.body, { key: "?", shiftKey: true });
    });
    expect(useAppStore.getState().helpOpen).toBe(true);
  });

  it("global search routes to the search collection", async () => {
    renderApp();
    act(() => useAppStore.getState().navigate({ runId: "run-aaaaaaaa", collection: "files" }));
    const input = screen.getByLabelText("전체 검색어");
    fireEvent.change(input, { target: { value: "powershell" } });
    fireEvent.submit(input);
    expect(window.location.hash).toBe("#/case/run-aaaaaaaa/explore/search?q=powershell");
  });
});
