/**
 * Hex helpers ported from v1 rapidtriage/web/static/app_hexview.js:
 * 16 bytes/row, row parsing from the `source-hex-range` API, offset input
 * parsing, and the forensic magic-byte signature scan.
 */

import type { HexRow } from "../../api/viewer";

export const BYTES_PER_ROW = 16;
/** One API request = 4 KiB = 256 rows (server cap is 64 KiB). */
export const CHUNK_BYTES = 4096;
export const ROWS_PER_CHUNK = CHUNK_BYTES / BYTES_PER_ROW;

export const HEX_SIGNATURES: ReadonlyArray<{ name: string; bytes: number[] }> = [
  { name: "PE/MZ", bytes: [0x4d, 0x5a] },
  { name: "ZIP", bytes: [0x50, 0x4b, 0x03, 0x04] },
  { name: "SQLite", bytes: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65] },
  { name: "PNG", bytes: [0x89, 0x50, 0x4e, 0x47] },
  { name: "JPEG", bytes: [0xff, 0xd8, 0xff] },
  { name: "GIF", bytes: [0x47, 0x49, 0x46, 0x38] },
  { name: "PDF", bytes: [0x25, 0x50, 0x44, 0x46] },
  { name: "ELF", bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { name: "RAR", bytes: [0x52, 0x61, 0x72, 0x21] },
  { name: "GZIP", bytes: [0x1f, 0x8b] },
  { name: "MFT FILE", bytes: [0x46, 0x49, 0x4c, 0x45] },
  { name: "EVTX", bytes: [0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65] },
  { name: "regf", bytes: [0x72, 0x65, 0x67, 0x66] },
  { name: "BMP", bytes: [0x42, 0x4d] },
  { name: "7z", bytes: [0x37, 0x7a, 0xbc, 0xaf] },
  { name: "VHD", bytes: [0x63, 0x6f, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x78] },
  { name: "EWF", bytes: [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00] },
];

export interface SignatureHit {
  name: string;
  offset: number;
  length: number;
}

/** Scan a byte array for signature offsets (absolute offsets). */
export function scanSignatures(bytes: Uint8Array, baseOffset = 0): SignatureHit[] {
  const hits: SignatureHit[] = [];
  for (const signature of HEX_SIGNATURES) {
    const needle = signature.bytes;
    outer: for (let i = 0; i + needle.length <= bytes.length; i++) {
      for (let j = 0; j < needle.length; j++) {
        if (bytes[i + j] !== needle[j]) continue outer;
      }
      hits.push({ name: signature.name, offset: baseOffset + i, length: needle.length });
    }
  }
  return hits.sort((a, b) => a.offset - b.offset);
}

/** Parse "aa bb cc" rows from the API into bytes. */
export function bytesFromHexRows(rows: ReadonlyArray<Pick<HexRow, "hex">> | undefined): Uint8Array {
  const out: number[] = [];
  for (const row of rows || []) {
    for (const token of String(row.hex || "").split(/\s+/)) {
      if (!token) continue;
      const value = Number.parseInt(token, 16);
      if (Number.isFinite(value)) out.push(value & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/** "0x1f0", "1f0h"-free hex with letters, or decimal. Returns null on bad input. */
export function parseOffsetInput(text: string): number | null {
  const raw = String(text || "")
    .trim()
    .toLowerCase();
  if (!raw) return null;
  const isPrefixed = raw.startsWith("0x");
  const body = isPrefixed ? raw.slice(2) : raw;
  if (!body) return null;
  const isHex = isPrefixed || /[a-f]/.test(body);
  if (isHex ? !/^[0-9a-f]+$/.test(body) : !/^[0-9]+$/.test(body)) return null;
  const value = Number.parseInt(body, isHex ? 16 : 10);
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export function formatOffset(offset: number, fileSize = 0): string {
  const width = fileSize > 0xffffffff ? 12 : 8;
  return `0x${offset.toString(16).padStart(width, "0")}`;
}

export function byteHex(value: number): string {
  return value.toString(16).padStart(2, "0");
}

export function byteAscii(value: number): string {
  return value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : ".";
}

export function rowCountForSize(size: number): number {
  return Math.max(1, Math.ceil(size / BYTES_PER_ROW));
}
