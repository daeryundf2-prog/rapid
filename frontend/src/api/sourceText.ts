// Reading the original as text: the source view's "더 보기" and text files the server previews only as bytes.

import { apiResponse } from "./client";
import { sourceFileUrl } from "./viewer";

const UTF16_SAMPLE_BYTES = 8192;

function startsWith(bytes: Uint8Array, prefix: readonly number[]): boolean {
  return prefix.every((value, index) => bytes[index] === value);
}

/** Share of NUL bytes at the even (0) or odd (1) positions of `sample`. */
function nulShare(sample: Uint8Array, parity: 0 | 1): number {
  let nul = 0;
  let total = 0;
  for (let index = parity; index < sample.length; index += 2) {
    total += 1;
    if (sample[index] === 0) nul += 1;
  }
  return total ? nul / total : 0;
}

/**
 * UTF-32 after its BOM, as Python's `utf-32` codec with `errors="replace"`: one U+FFFD per unit
 * outside Unicode or in the surrogate range, and one for a partial unit at the end of a complete
 * file. TextDecoder has no UTF-32.
 */
function decodeUtf32(bytes: Uint8Array, littleEndian: boolean, complete: boolean): string {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const whole = bytes.length - (bytes.length % 4);
  const parts: string[] = [];
  for (let offset = 4; offset < whole; offset += 4) {
    const point = view.getUint32(offset, littleEndian);
    const valid = point <= 0x10ffff && (point < 0xd800 || point > 0xdfff);
    parts.push(valid ? String.fromCodePoint(point) : "\ufffd");
  }
  if (complete && whole < bytes.length) parts.push("\ufffd");
  return parts.join("");
}

/**
 * Decode a text file in the order the server's text preview does — core/doc_text.decode_text_bytes,
 * reached from build_source_preview → docs.extract_text for TEXT_EXTS: BOM (UTF-8, UTF-32, UTF-16),
 * BOM-less UTF-16 (NUL in every other byte of the first 8 KB), strict UTF-8, strict CP949 (Korean
 * ANSI; the WHATWG euc-kr decoder is windows-949), else UTF-8 with U+FFFD.
 *
 * `complete` false: `bytes` is a prefix cut by a byte cap. A character split by the cut is dropped
 * instead of failing a strict decoder (which would switch the encoding) or adding a U+FFFD.
 */
export function decodeSourceText(bytes: Uint8Array, complete = true): string {
  const decode = (label: string, fatal = false, data: Uint8Array = bytes) =>
    new TextDecoder(label, { fatal }).decode(data, { stream: !complete });
  if (startsWith(bytes, [0xef, 0xbb, 0xbf])) return decode("utf-8");
  if (startsWith(bytes, [0xff, 0xfe, 0x00, 0x00])) return decodeUtf32(bytes, true, complete);
  if (startsWith(bytes, [0x00, 0x00, 0xfe, 0xff])) return decodeUtf32(bytes, false, complete);
  if (startsWith(bytes, [0xff, 0xfe])) return decode("utf-16le");
  if (startsWith(bytes, [0xfe, 0xff])) return decode("utf-16be");
  const sample = bytes.subarray(0, UTF16_SAMPLE_BYTES);
  if (sample.length >= 16) {
    const even = nulShare(sample, 0);
    const odd = nulShare(sample, 1);
    // The server drops an odd last byte before decoding BOM-less UTF-16.
    const units = bytes.subarray(0, bytes.length - (bytes.length % 2));
    if (odd > 0.3 && even < 0.05) return decode("utf-16le", false, units);
    if (even > 0.3 && odd < 0.05) return decode("utf-16be", false, units);
  }
  for (const label of ["utf-8", "euc-kr"]) {
    try {
      return decode(label, true);
    } catch (error) {
      // A fatal decoder throws TypeError on bytes outside its encoding: try the next one.
      if (!(error instanceof TypeError)) throw error;
    }
  }
  return decode("utf-8");
}

/**
 * The first `maxBytes` of the original. The body is read as a stream and cancelled at the cap, so
 * a large file is never transferred whole; `complete` is false when bytes were left unread.
 */
export async function fetchSourcePrefix(
  runId: string,
  path: string,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<{ bytes: Uint8Array<ArrayBuffer>; complete: boolean }> {
  const response = await apiResponse(sourceFileUrl(runId, path), { signal });
  // A null body is an empty one (Fetch gives a body to every response that has content).
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let complete = true;
  while (reader) {
    const { done, value } = await reader.read();
    if (done) break;
    const room = maxBytes - total;
    if (value.length > room) {
      chunks.push(value.subarray(0, room));
      total += room;
      complete = false;
      await reader.cancel().catch(() => undefined);
      break;
    }
    chunks.push(value);
    total += value.length;
  }
  const bytes = new Uint8Array(total);
  let cursor = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, cursor);
    cursor += chunk.length;
  }
  return { bytes, complete };
}

/** Read at most `maxBytes` of the original as text (the stream is cancelled after the cap). */
export async function fetchSourceTextPrefix(
  runId: string,
  path: string,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<{ text: string; bytesRead: number; complete: boolean }> {
  const { bytes, complete } = await fetchSourcePrefix(runId, path, maxBytes, signal);
  return { text: decodeSourceText(bytes, complete), bytesRead: bytes.length, complete };
}
