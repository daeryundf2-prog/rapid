import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { vi } from "vitest";

export interface RecordedCall {
  method: string;
  url: string;
  body: unknown;
}

type Responder = unknown | ((call: RecordedCall) => unknown);

/** Route table keyed `"METHOD /path-without-query"`; longest key wins by exact match then prefix. */
export function mockFetch(routes: Record<string, Responder>) {
  const calls: RecordedCall[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    const call: RecordedCall = {
      method,
      url,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    };
    calls.push(call);
    const path = url.split("?")[0] ?? url;
    const key = `${method} ${path}`;
    const hit = routes[key] ?? routes[`${method} ${url}`];
    if (hit === undefined) {
      return new Response(JSON.stringify({ detail: `unmocked ${key}` }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    }
    const payload = typeof hit === "function" ? (hit as (c: RecordedCall) => unknown)(call) : hit;
    if (payload instanceof Response) return payload;
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock };
}

export function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}
