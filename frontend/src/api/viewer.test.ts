import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchSourcePrefix, fetchSourceText } from "./viewer";

const utf8 = (text: string) => new TextEncoder().encode(text);

/** A response whose body arrives as `chunks`; `pulls` counts reads, `cancelled` the cancel. */
function chunkedResponse(chunks: Uint8Array[]) {
  const state = { pulls: 0, cancelled: false };
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      const next = chunks[state.pulls];
      state.pulls += 1;
      if (next) controller.enqueue(next);
      else controller.close();
    },
    cancel() {
      state.cancelled = true;
    },
  });
  return { response: new Response(body), state };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchSourcePrefix", () => {
  it("cancels a chunked body at the cap and never reads the rest", async () => {
    const chunks = [utf8("0123"), utf8("4567"), utf8("89ab"), utf8("cdef")];
    const { response, state } = chunkedResponse(chunks);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response),
    );
    const prefix = await fetchSourcePrefix("run-1", "C:/evidence/a.bin", 6);
    expect(new TextDecoder().decode(prefix.bytes)).toBe("012345");
    expect(prefix.complete).toBe(false);
    expect(state.cancelled).toBe(true);
    expect(state.pulls).toBeLessThan(chunks.length);
  });

  it("reads a body shorter than the cap whole and reports it complete", async () => {
    const { response, state } = chunkedResponse([utf8("012"), utf8("345")]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response),
    );
    const prefix = await fetchSourcePrefix("run-1", "C:/evidence/a.bin", 6);
    expect(new TextDecoder().decode(prefix.bytes)).toBe("012345");
    expect(prefix.complete).toBe(true);
    expect(state.cancelled).toBe(false);
  });

  it("treats a response without a body as empty", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(null, { status: 200 })),
    );
    await expect(fetchSourcePrefix("run-1", "C:/evidence/a.bin", 6)).resolves.toEqual({
      bytes: new Uint8Array(0),
      complete: true,
    });
  });
});

describe("fetchSourceText", () => {
  it("asks source-text, not source-file, for the capped and redacted text", async () => {
    const fetch = vi.fn(
      async (_input: RequestInfo | URL) =>
        new Response(JSON.stringify({ text: "a", size: 1, bytes_read: 1, complete: true, redacted: false }), {
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetch);
    await fetchSourceText("run-1", "C:/evidence/a.log", 2048);
    const url = new URL(String(fetch.mock.calls[0]?.[0]), "http://localhost");
    expect(url.pathname).toBe("/api/runs/run-1/source-text");
    expect(url.searchParams.get("path")).toBe("C:/evidence/a.log");
    expect(url.searchParams.get("max_bytes")).toBe("2048");
  });
});
