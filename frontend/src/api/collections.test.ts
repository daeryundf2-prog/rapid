import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installFetch, jsonResponse, quickJsonResponse } from "../features/grid/testSupport";
import { ApiError } from "./client";
import {
  fetchArtifactsPage,
  resetArtifactCountsCache,
  SORT_UNSUPPORTED_REASON,
  sortStateOf,
} from "./collections";

beforeEach(() => resetArtifactCountsCache());
afterEach(() => vi.unstubAllGlobals());

describe("fetchArtifactsPage row locators (record_index)", () => {
  it("uses the server's record_index as _index (filtered page), else the page position", async () => {
    installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            eventlog: {
              artifacts: [{ record_index: 9001 }, { record_index: 12 }, { details: {} }],
              total: null,
              pagination: { filtered: true, has_more: false },
            },
          },
        }),
    });
    const page = await fetchArtifactsPage("r1", "eventlog", 500, 3, undefined, "powershell");
    expect(page.rows.map((r) => r._index)).toEqual([9001, 12, 502]);
    expect(page.rows.every((r) => r._kind === "eventlog")).toBe(true);
    expect(page.sort).toBeUndefined();
  });

  it("all-kinds path filter also keeps record_index", async () => {
    installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            browser: { artifacts: [{ record_index: 41 }], pagination: { filtered: true } },
            eventlog: { artifacts: [{ record_index: 7 }, {}], pagination: { filtered: true } },
          },
        }),
    });
    const page = await fetchArtifactsPage("r1", undefined, 0, 10, undefined, "x");
    expect(page.rows.map((r) => `${r._kind}:${r._index}`)).toEqual([
      "browser:41",
      "eventlog:7",
      "eventlog:1",
    ]);
  });

  it("a building sort page has no rows and carries the sort state", async () => {
    const calls = installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            eventlog: {
              artifacts: [{ record_index: 1 }],
              total: 300000,
              sort: { key: "timestamp", order: "desc", status: "building", progress: 0.42 },
            },
          },
        }),
    });
    const page = await fetchArtifactsPage("r1", "eventlog", 0, 250, undefined, undefined, undefined, {
      key: "timestamp",
      order: "desc",
    });
    expect(calls[0]?.url).toContain("sort=timestamp");
    expect(calls[0]?.url).toContain("order=desc");
    expect(page.rows).toEqual([]);
    expect(page.total).toBe(300000);
    expect(page.sort).toEqual({ key: "timestamp", order: "desc", status: "building", progress: 0.42 });
  });
});

describe("sortStateOf", () => {
  const requested = { key: "details.a", order: "asc" as const };
  it("normalises the server object and clamps progress", () => {
    expect(sortStateOf({ sort: { status: "ready" } }, requested)).toEqual({
      key: "details.a",
      order: "asc",
      status: "ready",
      progress: 1,
    });
    expect(sortStateOf({ sort: { status: "building", progress: 3 } }, requested).progress).toBe(1);
    expect(
      sortStateOf({ sort: { status: "unsupported", reason: "inline payload" } }, requested),
    ).toMatchObject({
      status: "unsupported",
      reason: "inline payload",
    });
  });
  it("an older server (no sort object, sort_supported false) is unsupported with a Korean reason", () => {
    expect(sortStateOf({ sort_supported: false }, requested)).toMatchObject({
      status: "unsupported",
      reason: SORT_UNSUPPORTED_REASON,
    });
  });
});

describe("409 stale sort index", () => {
  it("retries once after 500 ms, then succeeds", async () => {
    vi.useFakeTimers();
    let n = 0;
    const calls = installFetch({
      "/artifacts": () => {
        n += 1;
        return n === 1
          ? quickJsonResponse({ detail: "stale" }, 409)
          : quickJsonResponse({ artifacts: { eventlog: { artifacts: [{ record_index: 3 }], total: 1 } } });
      },
    });
    const pending = fetchArtifactsPage("r1", "eventlog", 0, 10, undefined, undefined, undefined, {
      key: "timestamp",
      order: "asc",
    });
    await vi.advanceTimersByTimeAsync(499);
    expect(calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    const page = await pending;
    expect(calls).toHaveLength(2);
    expect(page.rows[0]?._index).toBe(3);
    vi.useRealTimers();
  });

  it("a second 409 surfaces as ApiError with the server detail", async () => {
    vi.useFakeTimers();
    installFetch({ "/artifacts": () => quickJsonResponse({ detail: "file changed" }, 409) });
    const pending = fetchArtifactsPage("r1", "eventlog", 0, 10).catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(500);
    const error = await pending;
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).message).toBe("file changed");
    vi.useRealTimers();
  });
});
