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

/**
 * A Response stand-in whose body resolves as a plain promise (no stream I/O), so tests on fake
 * timers settle by flushing microtasks alone (deterministic polling tests).
 */
export function quickJsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: new Headers({ "content-type": "application/json" }),
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
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
    selectionScope: null,
    commands: new Map(),
    visibleColumnIds: null,
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

export interface SortedArtifactsOptions {
  kind?: string;
  total?: number;
  /** Responses with `status: "building"` before the index is ready (per sort key/order). */
  buildPolls?: number;
  /** Keys the server refuses (`status: "unsupported"`). */
  unsupported?: string[];
  /** `locate=` requests answered with `status: "building"` before the position is given. */
  locateBuildPolls?: number;
}

/**
 * Mock of `GET /artifacts` for one kind implementing the artifact-columns §4.1
 * contract: `record_index` on every row, `sort=`/`order=` over the whole kind
 * with a `sort` state object (building → ready), `unsupported` keys, and
 * `locate=<record_index>` → `sort.position` (null while building / not found).
 * Record i has details.run_count = (i * 7) % total and a 700-char message.
 */
export function sortedArtifactsHandler(options: SortedArtifactsOptions = {}): Handler {
  const kind = options.kind ?? "windows-prefetch";
  const total = options.total ?? 30;
  const records = Array.from({ length: total }, (_, i) => ({
    artifact_type: "prefetch-file",
    path: `C:/Windows/Prefetch/APP${i}.EXE-1234.pf`,
    details: {
      executable_hint: `APP${i}.EXE`,
      run_count: (i * 7) % total,
      volume_serial: `VS-${i}`,
      last_run_at: `2026-01-01T00:00:${String(i % 60).padStart(2, "0")}Z`,
    },
    record_index: i,
  }));
  const polls = new Map<string, number>();
  let locatePolls = 0;
  return (url) => {
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? 250);
    const sortKey = url.searchParams.get("sort");
    const order = (url.searchParams.get("order") ?? "asc") as "asc" | "desc";
    let rows = records;
    let sort: Record<string, unknown> | undefined;
    if (sortKey) {
      if (options.unsupported?.includes(sortKey)) {
        sort = { key: sortKey, order, status: "unsupported", progress: 0, reason: "비스칼라 키입니다" };
      } else if (url.searchParams.has("locate") && locatePolls < (options.locateBuildPolls ?? 0)) {
        locatePolls += 1;
        return quickJsonResponse({
          artifacts: {
            [kind]: {
              artifacts: [],
              total,
              sort: { key: sortKey, order, status: "building", progress: 0.9, position: null },
            },
          },
        });
      } else {
        const id = `${sortKey}:${order}`;
        const seen = polls.get(id) ?? 0;
        polls.set(id, seen + 1);
        const building = seen < (options.buildPolls ?? 0);
        sort = {
          key: sortKey,
          order,
          status: building ? "building" : "ready",
          progress: building ? (seen + 1) / ((options.buildPolls ?? 0) + 1) : 1,
        };
        if (building) {
          if (url.searchParams.has("locate")) sort.position = null;
          return quickJsonResponse({
            artifacts: { [kind]: { artifacts: [], total, sort, sort_supported: true } },
          });
        }
        const field = sortKey.replace(/^details\./, "");
        rows = [...records].sort((a, b) => {
          const av = (a.details as Record<string, unknown>)[field] as number;
          const bv = (b.details as Record<string, unknown>)[field] as number;
          return order === "desc" ? bv - av : av - bv;
        });
        const locate = url.searchParams.get("locate");
        if (locate !== null) {
          const at = rows.findIndex((r) => r.record_index === Number(locate));
          sort.position = at >= 0 ? at : null;
        }
      }
    }
    return quickJsonResponse({
      artifacts: {
        [kind]: {
          artifacts: sort?.status === "unsupported" ? [] : rows.slice(offset, offset + limit),
          total,
          ...(sort ? { sort, sort_supported: sort.status !== "unsupported" } : {}),
        },
      },
    });
  };
}
