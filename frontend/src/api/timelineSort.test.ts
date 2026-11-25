import { afterEach, describe, expect, it, vi } from "vitest";
import { installFetch, jsonResponse } from "../features/grid/testSupport";
import { parseHash } from "../router";
import { fetchTimelinePage } from "./collections";

afterEach(() => vi.unstubAllGlobals());

describe("timeline server sort", () => {
  it("asks the server to sort the whole timeline and reports its sort state", async () => {
    const calls = installFetch({
      "/timeline": () =>
        jsonResponse({
          events: [{ record_index: 9, timestamp: "2024-01-01T00:00:00Z" }],
          matched: 5000,
          pagination: { total: 5000, matched: 5000, has_more: true },
          sort: { key: "timestamp", order: "desc", status: "ready", progress: 1 },
        }),
    });
    const page = await fetchTimelinePage("run-1", 0, 250, undefined, undefined, {
      key: "timestamp",
      order: "desc",
    });
    const params = new URL(calls[0]?.url ?? "", "http://x").searchParams;
    expect([params.get("sort"), params.get("order")]).toEqual(["timestamp", "desc"]);
    expect(page.total).toBe(5000);
    expect(page.sort).toMatchObject({ key: "timestamp", order: "desc", status: "ready" });
  });

  it("keeps sort= on a timeline route", () => {
    expect(parseHash("#/case/r1/explore/timeline?sort=timestamp:desc").sort).toEqual({
      key: "timestamp",
      order: "desc",
    });
  });
});
