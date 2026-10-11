// Test helpers for the viewer (mocked fetch keyed by API route name).
import { vi } from "vitest";
import type { SourcePreview } from "../../api/viewer";
import type { ViewerTarget } from "../../contracts/viewer";

export type Handler = (url: URL, init?: RequestInit) => unknown | Response | Promise<unknown | Response>;

export interface FetchCall {
  url: URL;
  init?: RequestInit;
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** Route by the last path segment (`source-preview`, `source-hex-range`, `bookmarks`, …). */
export function installFetch(routes: Record<string, Handler>): FetchCall[] {
  const calls: FetchCall[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), "http://localhost");
      calls.push({ url, init });
      const name = url.pathname.split("/").pop() || "";
      const handler = routes[name];
      if (!handler) return jsonResponse({ detail: `no mock for ${name}` }, 404);
      const result = await handler(url, init);
      return result instanceof Response ? result : jsonResponse(result);
    }),
  );
  return calls;
}

export function preview(overrides: Partial<SourcePreview>): SourcePreview {
  return {
    path: "C:/evidence/file.bin",
    name: "file.bin",
    extension: ".bin",
    size: 64,
    mime_type: "application/octet-stream",
    preview_type: "binary",
    text: "",
    truncated: false,
    message: "",
    ...overrides,
  };
}

export function metadata(path: string, size: number, sha256?: string) {
  return {
    path,
    name: path.split("/").pop(),
    extension: "",
    size,
    modified_at: "2026-10-01T00:00:00+00:00",
    created_at: "2026-10-01T00:00:00+00:00",
    mime_type: "application/octet-stream",
    hashes: sha256 ? { md5: "m", sha1: "s", sha256 } : {},
    hash_status: sha256 ? "computed" : "not-requested",
  };
}

export function target(overrides: Partial<ViewerTarget> = {}): ViewerTarget {
  return {
    runId: "run-1",
    ref: { collection: "files", locator: "/candidates/7" },
    sourcePath: "C:/evidence/file.bin",
    ...overrides,
  };
}

/** Hex rows for `length` bytes starting at `offset`, byte value = (offset + i) & 0xff. */
export function hexRows(offset: number, length: number, fill?: (absolute: number) => number) {
  const rows = [];
  for (let rel = 0; rel < length; rel += 16) {
    const bytes: number[] = [];
    for (let i = rel; i < Math.min(rel + 16, length); i++)
      bytes.push(fill ? fill(offset + i) : (offset + i) & 0xff);
    rows.push({
      offset: offset + rel,
      offset_hex: `0x${(offset + rel).toString(16).padStart(8, "0")}`,
      hex: bytes.map((b) => b.toString(16).padStart(2, "0")).join(" "),
      ascii: bytes.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join(""),
    });
  }
  return rows;
}

export function hexRangeHandler(size: number, fill?: (absolute: number) => number): Handler {
  return (url) => {
    const offset = Number(url.searchParams.get("offset"));
    const length = Math.min(Number(url.searchParams.get("length")), size - offset);
    return {
      offset,
      offset_hex: `0x${offset.toString(16)}`,
      end_offset_exclusive: offset + length,
      length_returned: length,
      size,
      rows: hexRows(offset, length, fill),
    };
  };
}
