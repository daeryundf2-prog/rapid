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
