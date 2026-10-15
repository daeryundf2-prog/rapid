import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installFetch, jsonResponse } from "../features/grid/testSupport";
import { fetchArtifactsPage, resetArtifactCountsCache } from "./collections";

// Mock of the cross-kind typed listing (artifact_filter.filter_across_kinds): kinds in request
// order, rows matching `artifact_type`; `after=<kind>:<record_index>:<matched>` resumes behind
// the last scanned row; a scan cap ends a window early with `truncated: true` (possibly 0 rows).
const KINDS = ["windows-system", "browser"];
type Rec = { artifact_type: string; path: string; details: object };
const RECORDS: Record<string, Rec[]> = {
  "windows-system": Array.from({ length: 7 }, (_, i) => ({
    artifact_type: i % 2 ? "wer-report" : "web-server-log",
    path: `C:/s/${i}`,
    details: {},
  })),
  browser: Array.from({ length: 5 }, (_, i) => ({
    artifact_type: "web-server-log",
    path: `C:/b/${i}`,
    details: {},
  })),
};

function crossKindServer(calls: string[], records: Record<string, Rec[]> = RECORDS, scanCap = 100_000) {
  return (url: URL) => {
    calls.push(url.search);
    const types = url.searchParams.getAll("artifact_type");
    const limit = Number(url.searchParams.get("limit") ?? 250);
    const after = url.searchParams.get("after");
    let pos = 0;
    let start = 0;
    let matched = 0;
    let skip = Number(url.searchParams.get("offset") ?? 0);
    if (after) {
      const [kind, index, count] = after.split(":");
      pos = KINDS.indexOf(kind as string);
      start = Number(index) + 1;
      matched = Number(count);
      skip = matched;
    }
    const base = skip;
    const order: Array<[string, number]> = [];
    const byKind: Record<string, unknown[]> = Object.fromEntries(KINDS.map((k) => [k, []]));
    let last: [string, number] | null = null;
    let hasMore = false;
    let exhausted = true;
    let scanned = 0;
    outer: for (let p = pos; p < KINDS.length; p++) {
      const kind = KINDS[p] as string;
      const rows = records[kind] ?? [];
      for (let i = p === pos ? start : 0; i < rows.length; i++) {
        if (scanned >= scanCap) {
          exhausted = false;
          break outer;
        }
        scanned += 1;
        const row = rows[i] as Rec;
        if (types.includes(row.artifact_type)) {
          if (order.length >= limit) {
            hasMore = true;
            exhausted = false;
            break outer;
          }
          if (matched >= skip) {
            byKind[kind]?.push({ ...row, record_index: i });
            order.push([kind, i]);
          }
          matched += 1;
        }
        last = [kind, i];
      }
    }
    let nextAfter = !exhausted && last ? `${last[0]}:${last[1]}:${matched}` : null;
    if (!exhausted && !last && after) nextAfter = after;
    return jsonResponse({
      artifacts: Object.fromEntries(
        KINDS.map((k) => [k, { artifacts: byKind[k], record_count: records[k]?.length }]),
      ),
      cross_kind: {
        kinds: KINDS,
        offset: base,
        limit,
        returned: order.length,
        order,
        record_count: 12,
        matched: exhausted ? matched : null,
        has_more: hasMore || !exhausted,
        next_offset: exhausted ? null : base + order.length,
        next_after: nextAfter,
        scanned,
        truncated: !exhausted && !hasMore,
      },
    });
  };
}

const page = (
  offset: number,
  limit: number,
  types: string[],
  restrict?: (a: readonly string[]) => string[],
) => fetchArtifactsPage("r1", undefined, offset, limit, undefined, undefined, restrict, undefined, types);
const keys = (rows: Array<Record<string, unknown>>) => rows.map((r) => `${r._kind}:${r._index}`);

beforeEach(() => resetArtifactCountsCache());
afterEach(() => vi.unstubAllGlobals());

describe("artifact_type across kinds: cursor paging (after=next_after)", () => {
  it("pages the matches as one collection, continuing with the cursor, never an offset rescan", async () => {
    const calls: string[] = [];
    installFetch({ "/artifacts": crossKindServer(calls) });
    const types = ["web-server-log"];
    const page0 = await page(0, 3, types);
    expect(keys(page0.rows)).toEqual(["windows-system:0", "windows-system:2", "windows-system:4"]);
    expect(page0.offset).toBe(0);
    expect(page0.total).toBeNull();
    expect(page0.hasMore).toBe(true);
    expect(page0.meta).toMatchObject({ matched: null, crossKind: true });

    const page1 = await page(3, 3, types);
    expect(keys(page1.rows)).toEqual(["windows-system:6", "browser:0", "browser:1"]);
    const page2 = await page(6, 3, types);
    expect(keys(page2.rows)).toEqual(["browser:2", "browser:3", "browser:4"]);
    expect(page2.total).toBe(9);
    expect(page2.meta?.matched).toBe(9);
    // Pages 1 and 2 resumed behind the previous page; only page 0 started from the top.
    const later = calls.slice(1).map((q) => new URLSearchParams(q));
    expect(later.every((q) => q.has("after") && !q.has("offset"))).toBe(true);
    expect(later.map((q) => q.get("after"))).toEqual(["windows-system:5:3", "browser:1:6"]);
    expect(later.every((q) => q.getAll("artifact_type").join() === "web-server-log")).toBe(true);
  });

  it("follows truncated (scan-capped) windows — even ones that return 0 rows — until the page is full", async () => {
    // eventlog-logon-session style: the first kind has no match, every window scans 2 rows.
    const records: Record<string, Rec[]> = {
      "windows-system": Array.from({ length: 6 }, (_, i) => ({
        artifact_type: "wer-report",
        path: `C:/s/${i}`,
        details: {},
      })),
      browser: Array.from({ length: 5 }, (_, i) => ({
        artifact_type: i === 1 || i >= 3 ? "eventlog-logon-session" : "other",
        path: `C:/b/${i}`,
        details: {},
      })),
    };
    const calls: string[] = [];
    installFetch({ "/artifacts": crossKindServer(calls, records, 2) });
    const types = ["eventlog-logon-session"];
    const first = await page(0, 2, types);
    expect(keys(first.rows)).toEqual(["browser:1", "browser:3"]);
    expect(first.offset).toBe(0);
    expect(first.hasMore).toBe(true);
    // Windows 1–3 were empty and truncated; each continued with its next_after.
    const afters = calls.slice(1).map((q) => new URLSearchParams(q).get("after"));
    expect(afters[0]).toBe("windows-system:1:0");
    expect(afters[1]).toBe("windows-system:3:0");
    const second = await page(2, 2, types);
    expect(keys(second.rows)).toEqual(["browser:4"]);
    expect(second.offset).toBe(2);
    expect(second.total).toBe(3);
    expect(second.hasMore).toBe(false);
  });

  it("a deep page without a stored cursor starts from the top and keeps only its own positions", async () => {
    const calls: string[] = [];
    installFetch({ "/artifacts": crossKindServer(calls) });
    const deep = await page(6, 3, ["web-server-log"]);
    expect(keys(deep.rows)).toEqual(["browser:2", "browser:3", "browser:4"]);
    expect(deep.offset).toBe(6);
    expect(deep.total).toBe(9);
    expect(new URLSearchParams(calls[0]).has("after")).toBe(false);
  });

  it("a category view sends its kinds (repeated kind=) and pages the same way", async () => {
    const calls: string[] = [];
    installFetch({
      "/artifacts": (url) =>
        url.searchParams.get("limit") === "1" && !url.searchParams.has("artifact_type")
          ? jsonResponse({
              artifacts: Object.fromEntries(KINDS.map((k) => [k, { artifacts: [], total: 5 }])),
            })
          : crossKindServer(calls)(url),
    });
    const restrict = (available: readonly string[]) => available.filter((k) => KINDS.includes(k));
    const cat = await page(0, 4, ["web-server-log"], restrict);
    expect(cat.kinds?.sort()).toEqual([...KINDS].sort());
    expect(new URLSearchParams(calls[0]).getAll("kind").sort()).toEqual([...KINDS].sort());
    expect(cat.rows).toHaveLength(4);
  });
});
