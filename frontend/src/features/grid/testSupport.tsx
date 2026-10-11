import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement, ReactNode } from "react";
import { vi } from "vitest";
import { useGridLocalStore } from "./adapter";
import { resetCaseDbHandles } from "./reviewActions";

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export interface FetchCall {
  url: string;
  method: string;
  body: unknown;
}

type Handler = (url: URL, init: RequestInit | undefined) => Response | Promise<Response>;

/** Replace global fetch with a router keyed by a path substring; records every call. */
export function installFetch(routes: Record<string, Handler>): FetchCall[] {
  const calls: FetchCall[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), "http://localhost");
      // The review-map overlay (GET /review-map) is ambient to every grid; unless a test
      // routes it explicitly it answers "no marks" and stays out of the recorded calls.
      if (
        url.pathname.endsWith("/review-map") &&
        !Object.keys(routes).some((k) => k.includes("review-map"))
      ) {
        return jsonResponse({ marks: [], exists: false, truncated: false });
      }
      calls.push({
        url: `${url.pathname}${url.search}`,
        method: init?.method ?? "GET",
        body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
      });
      const key = Object.keys(routes).find((k) => url.pathname.includes(k));
      if (!key) return jsonResponse({ detail: `unmocked ${url.pathname}` }, 404);
      return (routes[key] as Handler)(url, init);
    }),
  );
  return calls;
}

export function queryWrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Number.POSITIVE_INFINITY } },
  });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  return { client, wrapper };
}

export function renderWithClient(ui: ReactElement) {
  const { wrapper, client } = queryWrapper();
  return { client, ...render(ui, { wrapper }) };
}

export function resetGridStore(): void {
  resetCaseDbHandles();
  useGridLocalStore.setState({
    route: { runId: "run-1", collection: { id: "files" }, q: "", rowRef: null },
    selectedKeys: new Set<string>(),
    focusedRowKey: null,
    target: null,
    focusedRow: null,
    viewerFocusRequests: 0,
    density: "default",
    toasts: [],
    commands: new Map(),
  });
}

/** jsdom has no layout: give scroll containers a size so the virtualizer renders rows. */
export function mockLayout(width = 1000, height = 600): () => void {
  const proto = HTMLElement.prototype;
  const h = Object.getOwnPropertyDescriptor(proto, "offsetHeight");
  const w = Object.getOwnPropertyDescriptor(proto, "offsetWidth");
  Object.defineProperty(proto, "offsetHeight", { configurable: true, get: () => height });
  Object.defineProperty(proto, "offsetWidth", { configurable: true, get: () => width });
  return () => {
    if (h) Object.defineProperty(proto, "offsetHeight", h);
    if (w) Object.defineProperty(proto, "offsetWidth", w);
  };
}

/** Raw `files` API candidates `from..to-1`. */
export function fileCandidates(from: number, to: number) {
  return Array.from({ length: Math.max(0, to - from) }, (_, i) => ({
    path: `C:/evidence/dir${(from + i) % 7}/file-${from + i}.txt`,
    name: `file-${from + i}.txt`,
    extension: ".txt",
    size: 1000 + (from + i),
    modified_at: `2026-01-01T00:00:${String((from + i) % 60).padStart(2, "0")}Z`,
    categories: ["document"],
  }));
}

/** Files endpoint serving `total` rows with offset/limit paging. */
export function filesHandler(total: number): Handler {
  return (url) => {
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? 0);
    return jsonResponse({
      candidates: fileCandidates(offset, Math.min(offset + limit, total)),
      total,
      offset,
      limit,
    });
  };
}
