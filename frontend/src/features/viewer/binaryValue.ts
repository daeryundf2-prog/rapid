/**
 * Registry binary values (viewer redesign §9): hex text → bytes → a 16-byte hex dump, plus the
 * UTF-16LE strings in it. Parser-supplied `utf16le_strings` that are mostly non-printable
 * (binary read as UTF-16) are hidden with a note instead of shown as if they were text.
 */

/** Bytes of a hex string ("01 0a ff", "010aff", "0x010aff"); null when it is not hex. */
export function bytesOfHex(value: unknown): Uint8Array | null {
  if (typeof value !== "string") return null;
  // `.reg` text ("hex:01,02", "hex(7):41,00,…" with "\" line continuations) or plain hex.
  const body = value
    .trim()
    .replace(/^hex(\([0-9a-f]+\))?:/i, "")
    .replace(/\\[\r\n\s]*/g, "")
    .replace(/^0x/i, "");
  const clean = body.replace(/[\s,:-]+/g, "");
  if (clean.length < 2 || clean.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(clean)) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export interface DumpLine {
  offset: string;
  hex: string;
  ascii: string;
}

/** Classic hex dump lines (offset · 16 bytes · ASCII), up to `max` bytes. */
export function hexDump(bytes: Uint8Array, max = 4096): DumpLine[] {
  const lines: DumpLine[] = [];
  const end = Math.min(bytes.length, max);
  for (let at = 0; at < end; at += 16) {
    const chunk = Array.from(bytes.slice(at, Math.min(at + 16, end)));
    lines.push({
      offset: at.toString(16).padStart(8, "0"),
      hex: chunk.map((b) => b.toString(16).padStart(2, "0")).join(" "),
      ascii: chunk.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join(""),
    });
  }
  return lines;
}

/** Printable: letters/digits/punctuation of any script, space; not controls / private use / replacement. */
function printable(ch: string): boolean {
  const code = ch.codePointAt(0) ?? 0;
  if (code < 0x20 || (code >= 0x7f && code < 0xa0)) return false;
  if (code === 0xfffd || (code >= 0xe000 && code <= 0xf8ff) || (code >= 0xd800 && code <= 0xdfff))
    return false;
  return /[\p{L}\p{N}\p{P}\p{S}\p{Zs}]/u.test(ch);
}

/** Share of non-printable characters (0..1). */
export function nonPrintableRatio(text: string): number {
  const chars = Array.from(text);
  if (!chars.length) return 1;
  return chars.filter((ch) => !printable(ch)).length / chars.length;
}

/** Strings above this non-printable share are binary read as UTF-16 — hidden. */
export const GARBAGE_RATIO = 0.2;

/** A UTF-16 string worth showing: mostly printable, and not one CJK-range glyph soup run. */
export function isReadableString(text: string): boolean {
  if (text.trim().length < 2) return false;
  if (nonPrintableRatio(text) > GARBAGE_RATIO) return false;
  // Binary read as UTF-16LE lands in CJK / Hangul / Yi blocks with no spaces or ASCII at all.
  const chars = Array.from(text);
  const ascii = chars.filter((ch) => (ch.codePointAt(0) ?? 0) < 0x80).length;
  const hangulSyllables = chars.filter((ch) => /[가-힣]/.test(ch)).length;
  const unusual = chars.filter((ch) => /[㐀-䶿ꀀ-꓏一-鿿Ā-ɏ]/.test(ch)).length;
  if (chars.length >= 4 && ascii === 0 && hangulSyllables === 0 && unusual / chars.length > 0.6) return false;
  return true;
}

/** UTF-16LE strings (≥ `min` printable characters) in the bytes. */
export function utf16Strings(bytes: Uint8Array, min = 4): string[] {
  const out: string[] = [];
  let run = "";
  const flush = () => {
    if (run.length >= min && isReadableString(run)) out.push(run);
    run = "";
  };
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const code = (bytes[i] as number) | ((bytes[i + 1] as number) << 8);
    const ch = String.fromCharCode(code);
    if (code !== 0 && printable(ch)) run += ch;
    else flush();
  }
  flush();
  return out;
}

/** Split parser `utf16le_strings` into readable ones and a count of hidden garbage. */
export function filterUtf16Strings(list: unknown): { shown: string[]; hidden: number } {
  const items = Array.isArray(list) ? list.filter((item): item is string => typeof item === "string") : [];
  const shown = items.filter(isReadableString);
  return { shown, hidden: items.length - shown.length };
}
