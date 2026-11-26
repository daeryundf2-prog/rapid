import { afterEach, describe, expect, it, vi } from "vitest";
import { decodeSourceText, fetchSourcePrefix, fetchSourceTextPrefix } from "./sourceText";

const utf8 = (text: string) => new TextEncoder().encode(text);
const bytes = (...values: number[]) => new Uint8Array(values);

/** UTF-16 LE bytes of `text` (BMP characters only). */
function utf16le(text: string): Uint8Array {
  const out = new Uint8Array(text.length * 2);
  for (let index = 0; index < text.length; index++) {
    const unit = text.charCodeAt(index);
    out[index * 2] = unit & 0xff;
    out[index * 2 + 1] = unit >> 8;
  }
  return out;
}

describe("decodeSourceText", () => {
  it("reads UTF-8", () => {
    expect(decodeSourceText(utf8("로그 line"))).toBe("로그 line");
  });

  it("drops a UTF-8 BOM", () => {
    expect(decodeSourceText(bytes(0xef, 0xbb, 0xbf, ...utf8("a,b")))).toBe("a,b");
  });

  it("reads UTF-16 LE with a BOM", () => {
    expect(decodeSourceText(bytes(0xff, 0xfe, ...utf16le("한글 reg")))).toBe("한글 reg");
  });

  it("reads BOM-less UTF-16 LE (NUL in every other byte)", () => {
    expect(decodeSourceText(utf16le("setup log line 0001"))).toBe("setup log line 0001");
  });

  it("reads CP949 (Korean ANSI) when the bytes are not UTF-8", () => {
    // "한글 ok" in CP949: 한 = C7 D1, 글 = B1 DB.
    expect(decodeSourceText(bytes(0xc7, 0xd1, 0xb1, 0xdb, 0x20, 0x6f, 0x6b))).toBe("한글 ok");
  });

  it("drops a character cut by the byte cap instead of switching encoding", () => {
    expect(decodeSourceText(utf8("가나").subarray(0, 5), false)).toBe("가");
    // CP949: a lead byte cut from its trail byte.
    expect(decodeSourceText(bytes(0xc7, 0xd1, 0xc7), false)).toBe("한");
  });

  // Expected values below are core/doc_text.decode_text_bytes's own output for the same bytes.
  it("treats a partial character at the end of a complete file as the server does", () => {
    // Strict UTF-8 and CP949 both fail, so UTF-8 with U+FFFD.
    expect(decodeSourceText(bytes(0x61, 0xf0))).toBe("a\ufffd");
    expect(decodeSourceText(bytes(0xc7, 0xd1, 0xc7))).toBe("\ufffd\ufffd\ufffd");
  });

  it("drops the odd last byte of BOM-less UTF-16, as the server does", () => {
    expect(decodeSourceText(bytes(...utf16le("setup log line 0001"), 0x78))).toBe("setup log line 0001");
  });

  it("reads UTF-32 with a BOM (checked before the UTF-16 BOM it starts with)", () => {
    const le = bytes(0xff, 0xfe, 0, 0, 0x41, 0, 0, 0, 0x00, 0xf6, 0x01, 0x00, 0x5c, 0xd5, 0, 0);
    expect(decodeSourceText(le)).toBe("A😀한");
    expect(decodeSourceText(bytes(0, 0, 0xfe, 0xff, 0, 0, 0, 0x41, 0, 0, 0xd5, 0x5c))).toBe("A한");
    // A surrogate or a value past U+10FFFF is one U+FFFD per unit.
    expect(decodeSourceText(bytes(0xff, 0xfe, 0, 0, 0, 0xd8, 0, 0, 0, 0, 0x11, 0, 0x41, 0, 0, 0))).toBe(
      "\ufffd\ufffdA",
    );
    // A partial unit: U+FFFD at the end of the file, dropped at the byte cap.
    expect(decodeSourceText(bytes(0xff, 0xfe, 0, 0, 0x41, 0, 0, 0, 0x42, 0))).toBe("A\ufffd");
    expect(decodeSourceText(bytes(0xff, 0xfe, 0, 0, 0x41, 0, 0, 0, 0x42, 0), false)).toBe("A");
  });
});

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

describe("fetchSourcePrefix", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

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

describe("fetchSourceTextPrefix", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("stops at the byte cap and reports the text as incomplete", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("0123456789")),
    );
    await expect(fetchSourceTextPrefix("run-1", "C:/evidence/a.log", 4)).resolves.toEqual({
      text: "0123",
      bytesRead: 4,
      complete: false,
    });
  });

  it("drops a character the cap cuts in two", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(utf8("가나다"))),
    );
    await expect(fetchSourceTextPrefix("run-1", "C:/evidence/a.log", 5)).resolves.toEqual({
      text: "가",
      bytesRead: 5,
      complete: false,
    });
  });
});
