import { afterEach, describe, expect, it, vi } from "vitest";
import { decodeSourceText, fetchSourceTextPrefix } from "./sourceText";

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
    expect(decodeSourceText(utf8("가나").subarray(0, 5))).toBe("가");
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
});
