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
 * Decode a text file the way the server preview does (core/doc_text.decode_text_bytes): BOM
 * (UTF-8/16), BOM-less UTF-16 (NUL in every other byte), strict UTF-8, strict CP949 (Korean ANSI),
 * else UTF-8 with U+FFFD. A character cut by the byte cap at the end is dropped, not an error.
 */
export function decodeSourceText(bytes: Uint8Array): string {
  const decode = (label: string, fatal = false) =>
    new TextDecoder(label, { fatal }).decode(bytes, { stream: true });
  if (startsWith(bytes, [0xef, 0xbb, 0xbf])) return decode("utf-8");
  if (startsWith(bytes, [0xff, 0xfe])) return decode("utf-16le");
  if (startsWith(bytes, [0xfe, 0xff])) return decode("utf-16be");
  const sample = bytes.subarray(0, UTF16_SAMPLE_BYTES);
  if (sample.length >= 16) {
    const even = nulShare(sample, 0);
    const odd = nulShare(sample, 1);
    if (odd > 0.3 && even < 0.05) return decode("utf-16le");
    if (even > 0.3 && odd < 0.05) return decode("utf-16be");
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

/** Read at most `maxBytes` of the original as text (the stream is cancelled after the cap). */
export async function fetchSourceTextPrefix(
  runId: string,
  path: string,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<{ text: string; bytesRead: number; complete: boolean }> {
  const response = await apiResponse(sourceFileUrl(runId, path), { signal });
  const body = response.body;
  if (!body) {
    const buffer = new Uint8Array(await response.arrayBuffer());
    const slice = buffer.slice(0, maxBytes);
    return {
      text: decodeSourceText(slice),
      bytesRead: slice.length,
      complete: buffer.length <= maxBytes,
    };
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let complete = true;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const room = maxBytes - total;
    if (value.length > room) {
      chunks.push(value.slice(0, room));
      total += room;
      complete = false;
      await reader.cancel().catch(() => undefined);
      break;
    }
    chunks.push(value);
    total += value.length;
  }
  const merged = new Uint8Array(total);
  let cursor = 0;
  for (const chunk of chunks) {
    merged.set(chunk, cursor);
    cursor += chunk.length;
  }
  return { text: decodeSourceText(merged), bytesRead: total, complete };
}
