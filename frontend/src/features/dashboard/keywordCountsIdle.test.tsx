// T-130 browser check (verify-wb5-7: 3 × /search in 300 idle s on IMG-B): the 키워드 일치 card's
// /search requests are its one-off counts, one per keyword in turn (each a slow scan on a large
// run), never a poll: once every keyword is counted the card sends nothing more while idle.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { quickJsonResponse } from "../grid/testSupport";
import { KeywordCard } from "./cards";
import type { KeywordRow } from "./model";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const rows: KeywordRow[] = ["계좌", "송금", "삭제"].map((query) => ({
  id: query,
  label: query,
  query,
  source: "profile",
}));

describe("키워드 일치 counts (T-130)", () => {
  it("one /search per keyword, then nothing for 5 idle minutes", async () => {
    vi.useFakeTimers();
    const urls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        urls.push(String(input));
        // A slow scan on a large run (about 100 s each, as measured on IMG-B).
        await new Promise((resolve) => setTimeout(resolve, 100_000));
        return quickJsonResponse({ summary: { match_count: 3 }, matches: [] });
      }),
    );
    const client = new QueryClient({ defaultOptions: { queries: { staleTime: 2_000 } } });
    render(
      <QueryClientProvider client={client}>
        <KeywordCard runId="r1" rows={rows} enabled onOpen={() => {}} />
      </QueryClientProvider>,
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5 * 60_000);
    });
    expect(urls.filter((url) => url.includes("/search?"))).toHaveLength(3);
    const counted = urls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5 * 60_000);
    });
    expect(urls.length).toBe(counted);
    client.clear();
  });
});
