// T-130: no retry on 4xx (except 408 / 429), 30 s idle poll, no poll while the tab is hidden.

import { focusManager, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { quickJsonResponse } from "../features/grid/testSupport";
import { ApiError } from "./errors";
import { MAX_QUERY_RETRIES, pollWhenVisible, shouldRetryQuery } from "./queryPolicy";
import { ACTIVE_POLL_MS, IDLE_POLL_MS, runsPollInterval, useRunsPoll } from "./runsProgress";

afterEach(() => {
  cleanup();
  focusManager.setFocused(undefined);
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("shouldRetryQuery", () => {
  it("never retries a 4xx except 408 and 429", () => {
    for (const status of [400, 401, 403, 404, 405, 409, 413, 422, 499]) {
      expect(shouldRetryQuery(0, new ApiError("x", status, null))).toBe(false);
    }
    for (const status of [408, 429]) {
      expect(shouldRetryQuery(0, new ApiError("x", status, null))).toBe(true);
    }
  });

  it("retries 5xx and network failures twice", () => {
    for (const error of [
      new ApiError("x", 500, null),
      new ApiError("x", 503, null),
      new ApiError("x", 0, null),
    ]) {
      expect(shouldRetryQuery(0, error)).toBe(true);
      expect(shouldRetryQuery(1, error)).toBe(true);
      expect(shouldRetryQuery(MAX_QUERY_RETRIES, error)).toBe(false);
    }
    expect(shouldRetryQuery(0, new TypeError("Failed to fetch"))).toBe(true);
    expect(shouldRetryQuery(2, new TypeError("Failed to fetch"))).toBe(false);
  });
});

describe("poll intervals", () => {
  it("keeps 1.5 s while processing and 30 s when idle", () => {
    expect(ACTIVE_POLL_MS).toBe(1500);
    expect(IDLE_POLL_MS).toBe(30_000);
    expect(runsPollInterval([{ run_id: "a", status: "running" } as never])).toBe(1500);
    expect(runsPollInterval([{ run_id: "a", status: "completed" } as never])).toBe(30_000);
  });

  it("is off while the document is hidden", () => {
    expect(pollWhenVisible(1500)).toBe(1500);
    expect(pollWhenVisible(false)).toBe(false);
    focusManager.setFocused(false);
    expect(pollWhenVisible(1500)).toBe(false);
    focusManager.setFocused(true);
    expect(pollWhenVisible(1500)).toBe(1500);
  });
});

function Probe() {
  useRunsPoll();
  return null;
}

async function idlePollsInFiveMinutes(): Promise<number> {
  vi.useFakeTimers();
  let calls = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      calls += 1;
      return quickJsonResponse({ runs: [{ run_id: "r1", status: "completed" }] });
    }),
  );
  const client = new QueryClient({ defaultOptions: { queries: { retry: shouldRetryQuery } } });
  render(
    <QueryClientProvider client={client}>
      <Probe />
    </QueryClientProvider>,
  );
  // Let the first request land, then count five idle minutes.
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
  const afterFirst = calls;
  await act(async () => {
    await vi.advanceTimersByTimeAsync(5 * 60_000);
  });
  client.clear();
  return calls - afterFirst;
}

describe("useRunsPoll network budget (QA-101)", () => {
  it("asks at most 10 times in 5 idle minutes", async () => {
    const n = await idlePollsInFiveMinutes();
    expect(n).toBeGreaterThan(0);
    expect(n).toBeLessThanOrEqual(10);
  });

  it("asks nothing while the tab stays hidden for 5 minutes", async () => {
    vi.useFakeTimers();
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        calls += 1;
        return quickJsonResponse({ runs: [{ run_id: "r1", status: "running" }] });
      }),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: shouldRetryQuery } } });
    render(
      <QueryClientProvider client={client}>
        <Probe />
      </QueryClientProvider>,
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    const loaded = calls;
    act(() => focusManager.setFocused(false));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5 * 60_000);
    });
    // Running → 1.5 s while visible; hidden → nothing.
    expect(calls - loaded).toBe(0);
    act(() => focusManager.setFocused(true));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    const visibleAgain = calls;
    expect(visibleAgain).toBeGreaterThan(loaded);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ACTIVE_POLL_MS * 2);
    });
    expect(calls).toBeGreaterThan(visibleAgain);
    client.clear();
  });
});
