import { act, configure, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetArtifactCountsCache } from "../../api/collections";
import type { CollectionQuery } from "../../contracts/collection";
import {
  filesHandler,
  installFetch,
  jsonResponse,
  queryWrapper,
  resetGridStore,
  sortedArtifactsHandler,
} from "./testSupport";
import { categoryScopeText, collectionQueryKey, PAGE_SIZE, useCollectionQuery } from "./useCollectionQuery";

// Async waits must not depend on machine speed (CI under load).
configure({ asyncUtilTimeout: 5000 });

const filesQuery: CollectionQuery = { ref: { id: "files" }, offset: 0, limit: PAGE_SIZE };

beforeEach(() => {
  resetGridStore();
  resetArtifactCountsCache();
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("useCollectionQuery paging", () => {
  it("fetches only the first page (250 rows) at first, with total and backend", async () => {
    const calls = installFetch({ "/files": filesHandler(600) });
    const { wrapper } = queryWrapper();
    const { result } = renderHook(() => useCollectionQuery(filesQuery, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.total).toBe(600));
    expect(calls.map((c) => c.url)).toEqual(["/api/runs/run-1/files?offset=0&limit=250"]);
    expect(result.current.pageCount).toBe(3);
    expect(result.current.loadedCount).toBe(250);
    expect(result.current.backend).toBe("file");
    expect(result.current.getRow(0)?.rowKey).toBe("files:/candidates/0");
    expect(result.current.getRow(250)).toBeUndefined();
  });

  it("ensureRange loads the viewed page and prefetches the next one; far pages stay unfetched", async () => {
    const calls = installFetch({ "/files": filesHandler(2000) });
    const { wrapper } = queryWrapper();
    const { result } = renderHook(() => useCollectionQuery(filesQuery, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.total).toBe(2000));
    act(() => result.current.ensureRange(0, 30));
    await waitFor(() => expect(result.current.getRow(260)?.rowKey).toBe("files:/candidates/260"));
    const offsets = calls.map((c) => new URL(c.url, "http://x").searchParams.get("offset"));
    expect(offsets.sort()).toEqual(["0", "250"]);
    // Jump (End key): only the target page and its successor are requested.
    act(() => result.current.ensureRange(1990, 1990));
    await waitFor(() => expect(result.current.getRow(1990)?.rowKey).toBe("files:/candidates/1990"));
    const all = calls.map((c) => new URL(c.url, "http://x").searchParams.get("offset"));
    expect(new Set(all)).toEqual(new Set(["0", "250", "1750"]));
  });

  it("ensureRange past the end is clamped to the last page", async () => {
    const calls = installFetch({ "/files": filesHandler(300) });
    const { wrapper } = queryWrapper();
    const { result } = renderHook(() => useCollectionQuery(filesQuery, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.total).toBe(300));
    act(() => result.current.ensureRange(290, 5000));
    await waitFor(() => expect(result.current.pagesLoaded).toBe(2));
    expect(calls.length).toBe(2);
  });

  it("uses stable keys: re-render does not refetch", async () => {
    const calls = installFetch({ "/files": filesHandler(100) });
    const { wrapper } = queryWrapper();
    const { result, rerender } = renderHook(() => useCollectionQuery({ ...filesQuery }, { runId: "run-1" }), {
      wrapper,
    });
    await waitFor(() => expect(result.current.total).toBe(100));
    rerender();
    rerender();
    expect(calls.length).toBe(1);
  });

  it("surfaces the search backend, truncated flag and elapsed time (whole collection)", async () => {
    const calls = installFetch({
      "/search": () =>
        jsonResponse({
          backend: "fts",
          truncated: true,
          elapsed_ms: 312,
          matches: [
            { source: "files", pointer: "/candidates/1", path: "C:/a.txt", title: "a", preview: "x" },
            { source: "docs-index", pointer: "/results/2", path: "C:/b.pdf", title: "b", preview: "y" },
          ],
        }),
    });
    const { wrapper } = queryWrapper();
    const q: CollectionQuery = {
      ref: { id: "search" },
      offset: 0,
      limit: PAGE_SIZE,
      extension: [".txt"],
      search: { keywords: ["powershell"], mode: "exact", hideKnownGood: true },
    };
    const { result } = renderHook(() => useCollectionQuery(q, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.total).toBe(2));
    expect(result.current.backend).toBe("fts");
    expect(result.current.truncated).toBe(true);
    expect(result.current.elapsedMs).toBe(312);
    const url = new URL(calls[0]?.url ?? "", "http://x");
    expect(url.searchParams.getAll("keyword")).toEqual(["powershell"]);
    expect(url.searchParams.get("search_mode")).toBe("exact");
    expect(url.searchParams.get("hide_known_good")).toBe("true");
    expect(url.searchParams.getAll("extension")).toEqual([".txt"]);
    expect(result.current.getRow(1)?.rowKey).toBe("search:docs-index:/results/2");
  });

  it("artifacts of one kind page through GET /artifacts?offset&limit and use the kind total", async () => {
    const calls = installFetch({
      "/artifacts": (url) => {
        const offset = Number(url.searchParams.get("offset"));
        const limit = Number(url.searchParams.get("limit"));
        const rows = Array.from({ length: Math.min(limit, 281595 - offset) }, (_, i) => ({
          artifact_type: "evtx_event",
          path: "C:/s.evtx",
          details: { message: `m${offset + i}` },
        }));
        return jsonResponse({
          artifacts: { eventlog: { artifacts: rows, total: 281595 }, browser: { artifacts: [], total: 0 } },
        });
      },
    });
    const { wrapper } = queryWrapper();
    const q: CollectionQuery = { ref: { id: "artifacts", kind: "eventlog" }, offset: 0, limit: PAGE_SIZE };
    const { result } = renderHook(() => useCollectionQuery(q, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.total).toBe(281595));
    expect(calls).toHaveLength(1);
    expect(result.current.pageCount).toBe(1127);
    expect(result.current.getRow(249)?.rowKey).toBe("artifacts:eventlog:/artifacts/249");
    expect(result.current.getRow(249)?.title).toBe("m249");
  });

  it("artifacts across all kinds map one global window onto per-kind offsets", async () => {
    const counts: Record<string, number> = { browser: 300, eventlog: 400 };
    const calls = installFetch({
      "/artifacts": (url) => {
        const offset = Number(url.searchParams.get("offset"));
        const limit = Number(url.searchParams.get("limit"));
        const artifacts: Record<string, unknown> = {};
        for (const [kind, n] of Object.entries(counts)) {
          artifacts[kind] = {
            total: n,
            artifacts: Array.from({ length: Math.max(0, Math.min(limit, n - offset)) }, (_, i) => ({
              artifact_type: kind,
              path: `C:/${kind}`,
              details: { name: `${kind}-${offset + i}` },
            })),
          };
        }
        return jsonResponse({ artifacts });
      },
    });
    const { wrapper } = queryWrapper();
    const q: CollectionQuery = { ref: { id: "artifacts" }, offset: 0, limit: 250 };
    const { result } = renderHook(() => useCollectionQuery(q, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.total).toBe(700));
    act(() => result.current.ensureRange(250, 250));
    await waitFor(() => expect(result.current.getRow(260)).toBeDefined());
    // Page 1 = global rows 250..499: 50 browser rows (250..299) then 200 eventlog rows (0..199).
    expect(result.current.getRow(250)?.title).toBe("browser-250");
    expect(result.current.getRow(300)?.title).toBe("eventlog-0");
    // Kind-local locators repeat across kinds; the row key carries the kind so keys stay unique.
    expect(result.current.getRow(300)?.rowKey).toBe("artifacts:eventlog:/artifacts/0");
    expect(result.current.getRow(0)?.rowKey).toBe("artifacts:browser:/artifacts/0");
    expect(result.current.getRow(300)?.ref.kind).toBe("eventlog");
    expect(calls.length).toBeGreaterThan(1);
  });

  it("a category node pages only the run's kinds in that category (repeatable kind=)", async () => {
    const counts: Record<string, number> = { browser: 3, eventlog: 4, "windows-registry": 2, "odd-kind": 1 };
    const calls = installFetch({
      "/artifacts": (url) => {
        const offset = Number(url.searchParams.get("offset") ?? 0);
        const limit = Number(url.searchParams.get("limit"));
        const wanted = url.searchParams.getAll("kind");
        const artifacts: Record<string, unknown> = {};
        for (const [kind, n] of Object.entries(counts)) {
          if (wanted.length > 0 && !wanted.includes(kind)) continue;
          artifacts[kind] = {
            total: n,
            artifacts: Array.from({ length: Math.max(0, Math.min(limit, n - offset)) }, (_, i) => ({
              artifact_type: kind,
              path: `C:/${kind}`,
              details: { name: `${kind}-${offset + i}` },
            })),
          };
        }
        return jsonResponse({ artifacts });
      },
    });
    const { wrapper } = queryWrapper();
    const q: CollectionQuery = {
      ref: { id: "artifacts", category: "operating-system" },
      offset: 0,
      limit: PAGE_SIZE,
    };
    const { result } = renderHook(() => useCollectionQuery(q, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.total).toBe(6));
    expect(result.current.loadedRows.map((r) => r.title)).toEqual([
      "eventlog-0",
      "eventlog-1",
      "eventlog-2",
      "eventlog-3",
      "windows-registry-0",
      "windows-registry-1",
    ]);
    expect(result.current.category).toEqual({ id: "operating-system", label: "운영 체제", kindCount: 2 });
    expect(categoryScopeText(result.current.category as NonNullable<typeof result.current.category>)).toBe(
      "범주: 운영 체제 (2 유형)",
    );
    const kinds = calls.flatMap((c) => new URL(c.url, "http://x").searchParams.getAll("kind"));
    expect(kinds).not.toContain("browser");

    // Path filter: one request carrying every category kind.
    const filtered: CollectionQuery = { ...q, pathContains: "C:" };
    const before = calls.length;
    const { result: second } = renderHook(() => useCollectionQuery(filtered, { runId: "run-1" }), {
      wrapper,
    });
    await waitFor(() => expect(second.current.total).toBe(6));
    const filterCalls = calls.slice(before).map((c) => new URL(c.url, "http://x").searchParams);
    expect(filterCalls.some((p) => p.getAll("kind").join(",") === "eventlog,windows-registry")).toBe(true);
  });

  it("the 기타 category picks up kinds missing from the taxonomy", async () => {
    installFetch({
      "/artifacts": (url) => {
        const wanted = url.searchParams.getAll("kind");
        const all: Record<string, unknown> = {
          browser: { total: 1, artifacts: [{ artifact_type: "browser", details: { name: "b" } }] },
          "odd-kind": { total: 1, artifacts: [{ artifact_type: "odd", details: { name: "odd-0" } }] },
        };
        const artifacts = Object.fromEntries(
          Object.entries(all).filter(([k]) => wanted.length === 0 || wanted.includes(k)),
        );
        return jsonResponse({ artifacts });
      },
    });
    const { wrapper } = queryWrapper();
    const q: CollectionQuery = { ref: { id: "artifacts", category: "other" }, offset: 0, limit: PAGE_SIZE };
    const { result } = renderHook(() => useCollectionQuery(q, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.total).toBe(1));
    expect(result.current.getRow(0)?.ref.kind).toBe("odd-kind");
    expect(result.current.category?.label).toBe("기타");
  });

  it("review status filter applies to the whole collection", async () => {
    installFetch({
      "/case": () =>
        jsonResponse({
          exists: true,
          case: {
            bookmarks: [
              { bookmark_id: "a", review: { status: "relevant", include_in_report: false } },
              { bookmark_id: "b", review: { status: "excluded", include_in_report: false } },
              { bookmark_id: "c", review: { status: "relevant", include_in_report: true } },
            ],
          },
        }),
    });
    const { wrapper } = queryWrapper();
    const q: CollectionQuery = { ref: { id: "review", status: "relevant" }, offset: 0, limit: PAGE_SIZE };
    const { result } = renderHook(() => useCollectionQuery(q, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.total).toBe(2));
    expect(result.current.loadedRows.map((r) => r.rowKey)).toEqual([
      "review:bookmark:a",
      "review:bookmark:c",
    ]);
  });

  it("reports an error and retries via refetch", async () => {
    let fail = true;
    installFetch({
      "/files": (url, init) => (fail ? jsonResponse({ detail: "boom" }, 500) : filesHandler(5)(url, init)),
    });
    const { wrapper } = queryWrapper();
    const { result } = renderHook(() => useCollectionQuery(filesQuery, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.error?.message).toBe("boom"));
    fail = false;
    act(() => result.current.refetch());
    await waitFor(() => expect(result.current.total).toBe(5));
  });

  it("one artifact kind = one kind= request; text goes to path_contains and truncation/scan info is surfaced", async () => {
    const calls = installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            eventlog: {
              artifacts: [{ artifact_type: "e", path: "C:/x/Security.evtx", details: {} }],
              total: null,
              pagination: { filtered: true, scanned: 2000000, truncated: true, has_more: true },
            },
          },
        }),
    });
    const { wrapper } = queryWrapper();
    const q: CollectionQuery = {
      ref: { id: "artifacts", kind: "eventlog" },
      offset: 0,
      limit: 250,
      text: "security",
    };
    const { result } = renderHook(() => useCollectionQuery(q, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.loadedCount).toBe(1));
    const url = new URL(calls[0]?.url ?? "", "http://x");
    expect(url.searchParams.getAll("kind")).toEqual(["eventlog"]);
    expect(url.searchParams.get("path_contains")).toBe("security");
    expect(result.current.total).toBeNull();
    expect(result.current.truncated).toBe(true);
    expect(result.current.scanned).toBe(2000000);
    expect(result.current.canLoadMore).toBe(true);
  });
});

describe("useCollectionQuery server sort (artifact-columns §4.1)", () => {
  const sortedQuery = (order: "asc" | "desc"): CollectionQuery => ({
    ref: { id: "artifacts", kind: "windows-prefetch" },
    offset: 0,
    limit: PAGE_SIZE,
    sort: { key: "details.run_count", order },
  });

  /** Advance the fake clock (and flush promises / react-query's batched notifications). */
  const tick = (ms: number) =>
    act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
    });
  // quickJsonResponse bodies resolve as plain promises: flushing at the same instant settles them.
  const settle = async () => {
    for (let i = 0; i < 5; i += 1) await tick(0);
  };
  const artifactCalls = (calls: { url: string }[]) => calls.filter((c) => c.url.includes("/artifacts"));

  it("sends sort/order, re-requests exactly at 1000 ms while building, then pages in server order", async () => {
    vi.useFakeTimers();
    const calls = installFetch({ "/artifacts": sortedArtifactsHandler({ total: 30, buildPolls: 1 }) });
    const { wrapper } = queryWrapper();
    const { result } = renderHook(() => useCollectionQuery(sortedQuery("desc"), { runId: "run-1" }), {
      wrapper,
    });
    await settle();
    expect(result.current.sortState?.status).toBe("building");
    expect(result.current.sortState?.progress).toBeCloseTo(0.5);
    expect(result.current.loadedCount).toBe(0);
    const first = new URL(calls[0]?.url ?? "", "http://x");
    expect(first.searchParams.get("sort")).toBe("details.run_count");
    expect(first.searchParams.get("order")).toBe("desc");
    expect(first.searchParams.getAll("kind")).toEqual(["windows-prefetch"]);
    expect(artifactCalls(calls)).toHaveLength(1);
    await tick(999);
    expect(artifactCalls(calls)).toHaveLength(1);
    await tick(1);
    await settle();
    expect(artifactCalls(calls)).toHaveLength(2);
    // The 1000 ms re-request went out (asserted above); its background result reaches the hook on
    // React's own scheduler, so wait for the state (the clock no longer matters once ready).
    await vi.waitFor(() => expect(result.current.sortState?.status).toBe("ready"));
    expect(result.current.sortState?.status).toBe("ready");
    // run_count = (i*7) % 30 → max 29 at i = 17; the locator is the ORIGINAL JSONL index.
    expect(result.current.getRow(0)?.ref.locator).toBe("/artifacts/17");
    expect(result.current.getRow(1)?.ref.locator).toBe("/artifacts/4");
    // Ready: no further polling.
    await tick(5000);
    expect(artifactCalls(calls)).toHaveLength(2);
  });

  it("unmounting stops the building poll", async () => {
    vi.useFakeTimers();
    const calls = installFetch({ "/artifacts": sortedArtifactsHandler({ total: 30, buildPolls: 100 }) });
    const { wrapper } = queryWrapper();
    const { result, unmount } = renderHook(() => useCollectionQuery(sortedQuery("asc"), { runId: "run-1" }), {
      wrapper,
    });
    await settle();
    expect(result.current.sortState?.status).toBe("building");
    await tick(1000);
    expect(artifactCalls(calls)).toHaveLength(2);
    unmount();
    await tick(5000);
    expect(artifactCalls(calls)).toHaveLength(2);
  });

  it("re-sorting twice quickly leaves exactly one poller (the last sort)", async () => {
    vi.useFakeTimers();
    const calls = installFetch({ "/artifacts": sortedArtifactsHandler({ total: 30, buildPolls: 100 }) });
    const { wrapper } = queryWrapper();
    const { result, rerender } = renderHook(
      ({ order }: { order: "asc" | "desc" }) => useCollectionQuery(sortedQuery(order), { runId: "run-1" }),
      { wrapper, initialProps: { order: "asc" as "asc" | "desc" } },
    );
    await settle();
    expect(result.current.sortState?.order).toBe("asc");
    rerender({ order: "desc" });
    await settle();
    expect(result.current.sortState?.order).toBe("desc");
    rerender({ order: "asc" });
    await settle();
    expect(result.current.sortState?.order).toBe("asc");
    const before = artifactCalls(calls).length;
    await tick(3000);
    await settle();
    const polled = artifactCalls(calls).slice(before);
    expect(polled).toHaveLength(3);
    expect(polled.every((c) => c.url.includes("order=asc"))).toBe(true);
  });

  it("other collections and kind-less artifacts never send sort", async () => {
    const calls = installFetch({ "/files": filesHandler(10) });
    const { wrapper } = queryWrapper();
    const q: CollectionQuery = { ...filesQuery, sort: { key: "timestamp", order: "asc" } };
    const { result } = renderHook(() => useCollectionQuery(q, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.total).toBe(10));
    expect(calls[0]?.url).not.toContain("sort=");
    expect(result.current.sortState).toBeNull();
  });
});

describe("collectionQueryKey server filters", () => {
  it("keeps event-log channel groups, record fields and analysis details apart", () => {
    const eventlog: CollectionQuery = {
      ref: { id: "artifacts", kind: "eventlog" },
      offset: 0,
      limit: PAGE_SIZE,
    };
    const key = (query: CollectionQuery) => JSON.stringify(collectionQueryKey("r1", query, PAGE_SIZE));
    const keys = new Set([
      key(eventlog),
      key({ ...eventlog, channelGroups: ["security"] }),
      key({ ...eventlog, channelGroups: ["system"] }),
      key({ ...eventlog, channels: ["Security"] }),
      key({ ...eventlog, channelGroups: ["security"], fields: { service: ["Slack"] } }),
    ]);
    expect(keys.size).toBe(5);
    const ntfs: CollectionQuery = {
      ref: { id: "analysis", kind: "ntfs-meta", analysisId: "n1" },
      offset: 0,
      limit: PAGE_SIZE,
    };
    expect(key({ ...ntfs, detailFilters: { source: ["timestamp-mismatch"], in_use: ["true"] } })).not.toBe(
      key({ ...ntfs, detailFilters: { source: ["timestamp-mismatch"], in_use: ["false"] } }),
    );
  });
});
